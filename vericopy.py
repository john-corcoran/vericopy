#!/usr/bin/env python3

"""Vericopy: hash-verified and logged file consolidation between folders"""

import argparse
import dataclasses
import datetime
import hashlib
import logging
import logging.handlers
import multiprocessing
import multiprocessing.pool
import operator
import os
import pathlib
import platform
import shutil
import signal
import stat
import subprocess
import threading
import typing
import zipfile
import zlib

import tqdm


@dataclasses.dataclass
class FileMetadata:
    """Dataclass for each metadata item associated with a hashed file"""

    preferred_hash: str
    path: str
    source_folder: str
    size: int
    ctime: float
    mtime: float
    hash_values: typing.List[str]


class MsgCounterHandler(logging.Handler):
    """Custom logging handler to count number of calls per log level"""

    def __init__(self, *args, **kwargs) -> None:
        super(MsgCounterHandler, self).__init__(*args, **kwargs)
        self.count = {}
        self.count["WARNING"] = 0
        self.count["ERROR"] = 0

    def emit(self, record) -> None:
        levelname = record.levelname
        if levelname not in self.count:
            self.count[levelname] = 0
        self.count[levelname] += 1


def _prepare_logging(
    datetime_string: str,
    write_logs: bool,
    folder_path: typing.Optional[str],
    identifier: str,
    args: typing.Dict[str, typing.Any],
    show_debug: bool = False,
    write_debug: bool = False,
) -> typing.Tuple[logging.Logger, MsgCounterHandler]:
    """Prepare and return logging object to be used throughout script"""
    log = logging.getLogger(__name__)
    log.setLevel(logging.DEBUG)
    # 'Quiet' logger for when quiet flag used in functions
    quiet = logging.getLogger("quiet")
    quiet.setLevel(logging.ERROR)
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    if (write_logs or write_debug) and folder_path is not None:
        info_log = logging.FileHandler(
            os.path.join(folder_path, "{}_{}_info.log".format(datetime_string, identifier))
        )
        info_log.setLevel(logging.INFO)
        info_log.setFormatter(formatter)
        log.addHandler(info_log)
    if write_debug and folder_path is not None:
        debug_log = logging.FileHandler(
            os.path.join(folder_path, "{}_{}_debug.log".format(datetime_string, identifier))
        )
        debug_log.setLevel(logging.DEBUG)
        debug_log.setFormatter(formatter)
        log.addHandler(debug_log)
    console_handler = logging.StreamHandler()
    if show_debug:
        console_handler.setLevel(logging.DEBUG)
    else:
        console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    log.addHandler(console_handler)
    counter_handler = MsgCounterHandler()
    log.addHandler(counter_handler)
    # Log platform details and commandline arguments
    platform_detail_requests = [
        "python_version",
        "system",
        "machine",
        "platform",
        "version",
        "mac_ver",
    ]
    for platform_detail_request in platform_detail_requests:
        try:
            log.debug(
                "%s: %s", platform_detail_request, getattr(platform, platform_detail_request)()
            )
        except:  # pylint: disable=W0702
            pass
    # Sanitise zip password if present
    if "password" in args:
        if args["password"] is not None:
            args["password"] = "***"
    log.debug("commandline_args: %s", args)
    return log, counter_handler


def _log_listener(queue: multiprocessing.Queue) -> None:
    """Called as a separate thread and used by processes to forward log updates through"""
    while True:
        try:
            record = queue.get()
            if record is None:  # We send this as a sentinel to tell the listener to quit.
                break
            log = logging.getLogger(__name__)
            log.handle(record)  # No level or filter logic applied - just do it!
        except Exception:
            import sys, traceback

            print("Exception occurred with log listener:", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)


def _hash_pool_initializer() -> None:
    """Ignore CTRL+C in the hash worker processes (workers are daemonic so will close when the
    main process terminates)

    """
    signal.signal(signal.SIGINT, signal.SIG_IGN)


def _apply_write_permissions(func, path, exc_info) -> None:
    """Windows seems to be creating cache files as read only; this will be called on delete error"""
    os.chmod(path, stat.S_IWRITE)
    os.unlink(path)


def bytes_filesize_to_readable_str(bytes_filesize: int) -> str:
    """Convert bytes integer to kilobyte/megabyte/gigabyte/terabyte equivalent string"""
    if bytes_filesize < 1024:
        return "{} B"
    num = float(bytes_filesize)
    for unit in ["B", "KB", "MB", "GB"]:
        if abs(num) < 1024.0:
            return "{:.1f} {}".format(num, unit)
        num /= 1024.0
    return "{:.1f} {}".format(num, "TB")


def get_safe_path_name(path_name: str) -> str:
    """Return the provided file_name string with all non alphanumeric characters removed"""

    def safe_char(char):
        if char.isalnum():
            return char
        else:
            return "_"

    return "".join(safe_char(char) for char in path_name).rstrip("_")


def get_unused_output_path(file_path: str) -> str:
    """If a file already exists at path, get a similar new file path instead"""
    file_basename_noext = os.path.splitext(os.path.basename(file_path))[0]
    filename_suffix = 2
    while os.path.isfile(file_path):
        file_path = os.path.join(
            os.path.dirname(file_path),
            "{}_{}{}".format(
                file_basename_noext,
                filename_suffix,
                os.path.splitext(file_path)[1],
            ),
        )
        filename_suffix += 1
    return file_path


def get_list_as_str(list_to_convert: typing.List[str]) -> str:
    """Convert list into comma separated string, with each element enclosed in single quotes"""
    return ", ".join(["'{}'".format(list_item) for list_item in list_to_convert])


def get_missing_sources(
    source_paths: typing.List[str], files_only: bool = False
) -> typing.List[str]:
    """Return list of any source paths that aren't a file or a folder"""
    missing_sources = [
        source_path
        for source_path in source_paths
        if (not os.path.isdir(source_path) or files_only) and not os.path.isfile(source_path)
    ]
    return missing_sources


def compare_hashes_for_a_file(hash_set_1: typing.List[str], hash_set_2: typing.List[str]) -> bool:
    """Get a common hash between two sets of hashes, and compare if they match"""
    # Reverse sort on value length gives longest and therefore 'best' hash as first list item
    hash_set_1.sort(key=len, reverse=True)
    hash_set_2.sort(key=len, reverse=True)
    hash_set_1_preferred_hash = hash_set_1.pop(0)
    hash_set_2_preferred_hash = hash_set_2.pop(0)
    # Whittle away the preferred hashes until we have a set that match and therefore can be compared
    while len(hash_set_1_preferred_hash) != len(hash_set_2_preferred_hash):
        try:
            if len(hash_set_1_preferred_hash) < len(hash_set_2_preferred_hash):
                hash_set_2_preferred_hash = hash_set_2.pop(0)
            else:
                hash_set_1_preferred_hash = hash_set_1.pop(0)
        except IndexError:  # Will occur if we don't have a common hash type, so can't verify
            return False
    if hash_set_1_preferred_hash == hash_set_2_preferred_hash:
        return True
    return False


def get_file_paths_and_total_size(
    paths: typing.List[str],
    ignore_dotfiles: bool,
    ignore_windows_volume_folders: bool,
    log: typing.Optional[logging.Logger] = None,
) -> typing.Tuple[typing.List[str], int]:
    """Get list of file paths at a path (recurses subdirectories) and total size of directory"""
    if (
        log is None
    ):  # i.e. we are NOT calling from a separate process, so can get the logger ourself
        log = logging.getLogger(__name__)

    def walk_error(os_error: OSError) -> None:
        """Log any errors occurring during os.walk"""
        if log is not None:
            log.warning(
                "'%s' could not be accessed during folder scanning - any contents will not be"
                " processed. Try running script as admin",
                os_error.filename,
            )

    EXCLUDE_FOLDERS = {"$RECYCLE.BIN", "System Volume Information"}
    exclude_folder_seen_log = {}  # type: typing.Dict[str, typing.List[str]]
    files = []
    size = 0
    for path in sorted(paths):
        for root, dirs, filenames in os.walk(path, onerror=walk_error):
            if ignore_dotfiles:
                filenames = [f for f in filenames if not f[0] == "."]
                dirs[:] = [d for d in dirs if not d[0] == "."]
            if ignore_windows_volume_folders:
                for directory in [d for d in dirs if d in EXCLUDE_FOLDERS]:
                    if directory not in exclude_folder_seen_log:
                        exclude_folder_seen_log[directory] = []
                        exclude_folder_seen_log[directory].append(os.path.join(root, directory))
                        log.info(
                            "'%s' will not be processed (Windows system directory)",
                            os.path.join(root, directory),
                        )
                    else:
                        exclude_folder_seen_log[directory].append(os.path.join(root, directory))
                        log.warning(
                            "Excluded folder '%s' has been excluded more than once within path '%s'"
                            " - this is unexpected, as this folder should only be found in the root"
                            " of a drive. Be advised that the following folders will NOT be"
                            " processed: %s",
                            directory,
                            path,
                            get_list_as_str(exclude_folder_seen_log[directory]),
                        )
                dirs[:] = [d for d in dirs if not d in EXCLUDE_FOLDERS]
            for name in filenames:
                try:
                    size += os.path.getsize(os.path.join(root, name))
                    files.append(os.path.join(root, name))
                except (FileNotFoundError, PermissionError):
                    log.warning(
                        "File '%s' cannot be accessed and will not be processed - try running as"
                        " admin",
                        os.path.join(root, name),
                    )
    return sorted(files), size


def get_dict_from_hash_files(
    hash_file_paths: typing.List[str],
) -> typing.Dict[str, typing.Dict[str, typing.Any]]:
    """Turn contents of hash file at path into metadata dict object"""
    log = logging.getLogger(__name__)
    results = {}  # type: typing.Dict[str, typing.Dict[str, typing.Any]]
    for hash_file_path in hash_file_paths:
        with open(hash_file_path, "r", encoding="utf-8", errors="ignore") as file_handler:
            for line in file_handler:
                line_data = line.strip().split("|")
                try:
                    hash_values = [hash for hash in line_data[0:3] if hash != ""]
                    path = "|".join(line_data[3:-3])  # This should allow filenames containing pipes
                    size = line_data[-3]
                    ctime = line_data[-2]
                    mtime = line_data[-1]
                except IndexError:
                    log.error("Hash file '%s' does not match expected file format", hash_file_path)
                    return {}
                if path not in results:
                    results[path] = {}
                    results[path]["size"] = int(size)
                    results[path]["ctime"] = float(ctime)
                    results[path]["mtime"] = float(mtime)
                    results[path]["hashes"] = ["", "", ""]
                    for hash_value in hash_values:
                        results[path]["hashes"].append(hash_value)
                        if len(hash_value) == 64:
                            results[path]["sha256"] = hash_value
                            results[path]["hashes"][0] = hash_value
                        elif len(hash_value) == 40:
                            results[path]["sha1"] = hash_value
                            results[path]["hashes"][1] = hash_value
                        elif len(hash_value) == 32:
                            results[path]["md5"] = hash_value
                            results[path]["hashes"][2] = hash_value

                else:
                    # Alarm if the metadata has changed
                    if not compare_hashes_for_a_file(
                        results[path]["hashes"], hash_values
                    ) or results[path]["size"] != int(size):
                        log.error(
                            "While building pre computed hash dictionary, file path '%s' was"
                            " identified multiple times with different metadata across hash"
                            " files - hash files therefore cannot be used as verification"
                            " results would be inaccurate",
                            path,
                        )
                        return {}
    return results


def hash_file_at_path(filepath: str, algorithm: str) -> str:
    """Return str containing lowercase hash value of file at a file path"""
    block_size = 64 * 1024
    hasher = getattr(hashlib, algorithm)()
    with open(filepath, "rb") as file_handler:
        while True:
            data = file_handler.read(block_size)
            if not data:
                break
            hasher.update(data)
    return hasher.hexdigest()


def hash_data_stream(data: typing.IO[bytes], algorithm: str) -> str:
    """Return str containing lowercase hash value of a bytestream for a file"""
    blocksize = 64 * 1024
    hasher = getattr(hashlib, algorithm)()
    while True:
        block = data.read(blocksize)
        if not block:
            break
        hasher.update(block)
    return hasher.hexdigest()


def hash_files(
    file_paths: typing.List[str],
    source_folder: str,
    source_or_destination_str: str,
    hash_algorithms: typing.List[str],
    preferred_algorithm: str,
    log_folder_path: str,
    log_queue: typing.Optional[multiprocessing.Queue] = None,
    archive_flag: bool = False,
    only_archive_contents: bool = False,
    cache_path: str = "vericopy_cache",
    pre_computed_hash_values: typing.Dict[str, typing.Dict[str, typing.Any]] = {},
    zip_password: typing.Optional[str] = None,
    process_number: int = 0,
) -> typing.Dict[str, typing.List[FileMetadata]]:
    """Hash the provided file path list and return dict with hash value as key and list of tuples
    (file_path, source_folder, file_size, hash_values, file_ctime, file_mtime) as values

    """
    # Need to create the log object using a QueueHandler if running from a separate process
    if log_queue is not None:  # i.e. the function is being called from a separate process
        queue_handler = logging.handlers.QueueHandler(log_queue)
        log = logging.getLogger()
        log.addHandler(queue_handler)
        log.setLevel(logging.DEBUG)
    else:
        log = logging.getLogger(__name__)

    def get_metadata_from_precomputed(
        path: str,
        pre_computed_hash_values: typing.Dict[str, typing.Dict[str, typing.Any]],
        current_file_size: int,
        source_folder: str,
        log: logging.Logger,
    ) -> FileMetadata:
        hash_value = pre_computed_hash_values[path][preferred_algorithm]
        precomputed_size = pre_computed_hash_values[path]["size"]
        file_ctime = pre_computed_hash_values[path]["ctime"]
        file_mtime = pre_computed_hash_values[path]["mtime"]
        hash_values = pre_computed_hash_values[path]["hashes"]
        # Alarm if precomputed size and current size don't match
        if precomputed_size != current_file_size:
            log.warning(
                "File size of '%s' has changed since pre-computed hash data was"
                " generated - verification for this file will not be reliable",
                path,
            )
        return FileMetadata(
            preferred_hash=hash_value,
            path=path,
            source_folder=source_folder,
            size=precomputed_size,
            ctime=file_ctime,
            mtime=file_mtime,
            hash_values=hash_values,
        )

    def get_metadata_from_file(
        path: str,
        zip_archive: typing.Optional[zipfile.ZipFile],
        extracted_or_archive_path: typing.Optional[str],
        file_size: int,
        file_ctime: float,
        file_mtime: float,
        source_folder: str,
        hash_algorithms: typing.List[str],
        preferred_hash_length: int,
    ) -> FileMetadata:
        # Note: for Mac, looks like ctime is actually 'Date Added'
        hash_values = ["", "", ""]
        for algorithm in hash_algorithms:
            if zip_archive is not None and extracted_or_archive_path is not None:
                calculated_value = hash_data_stream(
                    zip_archive.open(extracted_or_archive_path), algorithm
                )
            elif extracted_or_archive_path is not None:
                calculated_value = hash_file_at_path(extracted_or_archive_path, algorithm)
            else:
                calculated_value = hash_file_at_path(path, algorithm)
            calculated_value_length = len(calculated_value)
            if calculated_value_length == preferred_hash_length:
                hash_value = calculated_value
            if calculated_value_length == 64:
                hash_values[0] = calculated_value
            elif calculated_value_length == 40:
                hash_values[1] = calculated_value
            else:
                hash_values[2] = calculated_value
        return FileMetadata(
            preferred_hash=hash_value,
            path=path,
            source_folder=source_folder,
            size=file_size,
            ctime=file_ctime,
            mtime=file_mtime,
            hash_values=hash_values,
        )

    def write_metadata_line(
        file_metadata: FileMetadata, OUTPUT_TEMPLATE: str, file_handler: typing.TextIO
    ):
        file_handler.write(
            OUTPUT_TEMPLATE.format(
                "|".join(file_metadata.hash_values),
                file_metadata.path,
                file_metadata.size,
                file_metadata.ctime,
                file_metadata.mtime,
            )
        )

    ARCHIVE_EXTENSIONS = {".zip", ".7z"}
    OUTPUT_TEMPLATE = "{}|{}|{}|{}|{}\n"
    if preferred_algorithm == "sha256":
        preferred_hash_length = 64
    elif preferred_algorithm == "sha1":
        preferred_hash_length = 40
    else:
        preferred_hash_length = 32
    log.debug("Beginning hashing for folder '%s' (process %s)", source_folder, process_number)

    hashes = {}  # type: typing.Dict[str, typing.List[FileMetadata]]
    hash_log_folder_path = os.path.join(log_folder_path, source_or_destination_str)
    pathlib.Path(hash_log_folder_path).mkdir(parents=True, exist_ok=True)
    safe_hash_log_file_name = get_safe_path_name(source_folder)
    if len(safe_hash_log_file_name) == 0:
        safe_hash_log_file_name = "root"
    hash_log_file_path = os.path.join(
        hash_log_folder_path, "{}.txt".format(safe_hash_log_file_name)
    )

    with open(hash_log_file_path, "w", encoding="utf-8", errors="ignore") as file_handler:
        for file_path in tqdm.tqdm(file_paths, position=process_number):
            log.debug("Processing '%s'", file_path)
            if not os.path.isfile(file_path):
                log.warning(
                    "File '%s' has either been deleted or is not a regular file (may be a Unix pipe"
                    " or socket) - will be skipped",
                    file_path,
                )
                continue
            file_extension = os.path.splitext(file_path)[1].lower()
            # Hash the file itself unless we're only_archiving_contents and it's a .zip/.7z
            if not only_archive_contents or file_extension not in ARCHIVE_EXTENSIONS:
                try:
                    local_file_metadata = pathlib.Path(file_path).stat()
                    file_size = local_file_metadata.st_size
                    # Get info from the pre-computed hash data if it is available
                    if file_path in pre_computed_hash_values:
                        file_metadata = get_metadata_from_precomputed(
                            file_path, pre_computed_hash_values, file_size, source_folder, log
                        )
                    else:
                        file_metadata = get_metadata_from_file(
                            file_path,
                            None,
                            None,
                            local_file_metadata.st_size,
                            local_file_metadata.st_ctime,
                            local_file_metadata.st_mtime,
                            source_folder,
                            hash_algorithms,
                            preferred_hash_length,
                        )
                except FileNotFoundError:
                    log.warning(
                        "File '%s' has been deleted in the time between scanning source path '%s'"
                        " and reaching this file in the hash queue. This file has not been"
                        " processed",
                        file_path,
                        source_folder,
                    )
                    continue
                except (PermissionError, OSError):
                    log.warning(
                        "PermissionError/OSError occurred for file '%s' - this file has not"
                        " been processed. Try running script as admin",
                        file_path,
                    )
                    continue
                if file_metadata.preferred_hash not in hashes:
                    hashes[file_metadata.preferred_hash] = []
                write_metadata_line(file_metadata, OUTPUT_TEMPLATE, file_handler)
                hashes[file_metadata.preferred_hash].append(file_metadata)
            if (archive_flag or only_archive_contents) and file_extension in ARCHIVE_EXTENSIONS:
                # Below does not account for 7z files, so ditched:
                # if zipfile.is_zipfile(file):
                try_7z_extraction = False
                if file_extension == ".zip":
                    try:
                        archive = zipfile.ZipFile(file_path, "r")
                    except zipfile.BadZipFile:
                        log.warning(
                            "'%s' is reported as 'not a ZIP file' by Python zipfile module - will"
                            " attempt 7z extraction",
                            file_path,
                        )
                        try_7z_extraction = True
                    except FileNotFoundError:
                        log.warning(
                            "File '%s' has been deleted in the time between scanning source path"
                            " '%s' and reaching this file in the hash queue. This file has not been"
                            " processed",
                            file_path,
                            source_folder,
                        )
                        continue
                    except (PermissionError, OSError):
                        log.warning(
                            "PermissionError/OSError occurred for accessing zip contents of file"
                            " '%s' - will try with 7zip, but script likely needs to be run as"
                            " admin",
                            file_path,
                        )
                        try_7z_extraction = True
                    if not try_7z_extraction:
                        for file_in_zip_path in sorted(archive.namelist()):
                            file_info = archive.getinfo(file_in_zip_path)
                            if not file_info.is_dir():
                                try:
                                    # Abandoned using native zip library for encrypted zips as
                                    # below: too slow
                                    # calculated_value = hash_data(
                                    #     archive.open(file_in_zip_path, pwd=b'infected')
                                    # )
                                    file_size = file_info.file_size
                                    zip_and_zipfile_path = os.path.join(file_path, file_in_zip_path)
                                    # Get info from the pre-computed hash data if it is available
                                    if zip_and_zipfile_path in pre_computed_hash_values:
                                        file_metadata = get_metadata_from_precomputed(
                                            zip_and_zipfile_path,
                                            pre_computed_hash_values,
                                            file_size,
                                            source_folder,
                                            log,
                                        )
                                    else:
                                        try:
                                            file_mtime = datetime.datetime(
                                                *file_info.date_time
                                            ).timestamp()
                                        except OverflowError:  # timestamp out of range for platform
                                            log.debug(
                                                "File '%s' within zip '%s' has an overflow"
                                                " timestamp",
                                                file_in_zip_path,
                                                file_path,
                                            )
                                            file_mtime = datetime.datetime.now().timestamp()
                                        file_ctime = file_mtime  # Just one datetime in zips
                                        file_metadata = get_metadata_from_file(
                                            zip_and_zipfile_path,
                                            archive,
                                            file_in_zip_path,
                                            file_size,
                                            file_ctime,
                                            file_mtime,
                                            source_folder,
                                            hash_algorithms,
                                            preferred_hash_length,
                                        )
                                    if file_metadata.preferred_hash not in hashes:
                                        hashes[file_metadata.preferred_hash] = []
                                    write_metadata_line(
                                        file_metadata, OUTPUT_TEMPLATE, file_handler
                                    )
                                    hashes[file_metadata.preferred_hash].append(file_metadata)
                                except RuntimeError:  # occurs if .zip is encrypted
                                    # No point trying 7z for an encrypted zip if we don't have
                                    # a password
                                    if zip_password is not None:
                                        try_7z_extraction = True
                                    else:
                                        log.info(
                                            "Cannot hash contents of encrypted zip '%s'", file_path
                                        )
                                    break  # Don't try and extract more files from the zip
                                except zlib.error:
                                    # Seen associated with 'invalid block lengths' for corrupted
                                    # zips - try anyway with 7z to be sure it can't be unzipped
                                    log.debug(
                                        "Zlib error when accessing data in '%s' - will try with"
                                        " 7zip",
                                        file_path,
                                    )
                                    try_7z_extraction = True
                                    break
                                except:
                                    log.exception(
                                        "Unexpected exception occurred when accessing data in zip"
                                        " file '%s' - will attempt with 7zip",
                                        file_path,
                                    )
                                    try_7z_extraction = True
                                    break
                        archive.close()
                else:
                    try_7z_extraction = True
                if try_7z_extraction:
                    if file_extension == ".7z":
                        log.debug("7z extract for 7z file: '%s'", file_path)
                        extract_type = "7z"
                    else:
                        log.debug("Password on file, will attempt 7z extract: '%s'", file_path)
                        extract_type = "zip"
                    extract_path = os.path.join(
                        cache_path, os.path.relpath(file_path, source_folder)
                    )
                    pathlib.Path(extract_path).mkdir(parents=True, exist_ok=True)
                    try:
                        try:
                            # Any password attempt below does not block files without a
                            # password being extracted - need to give an empty -p argument even
                            # if not password set, so errors on encrypted archives will be reported
                            args_for_7z = [
                                "7z",
                                "x",
                                file_path,
                                "-t{}".format(extract_type),
                                "-o{}".format(extract_path),
                                "-p{}".format(zip_password if zip_password is not None else ""),
                            ]
                            ret = subprocess.check_output(
                                args_for_7z,
                                stderr=subprocess.STDOUT,
                            )
                        except FileNotFoundError:
                            # Try again with 7z in Program Files path for Windows users
                            args_for_7z[0] = "C:\\Program Files\\7-Zip\\7z.exe"
                            ret = subprocess.check_output(
                                args_for_7z,
                                stderr=subprocess.STDOUT,
                            )
                        log.debug(ret)
                        for extracted_file_path in get_file_paths_and_total_size(
                            [extract_path],
                            ignore_dotfiles=False,  # override user option for zip file contents
                            ignore_windows_volume_folders=False,
                            log=log,  # Need to pass the log loaded with the QueueHandler
                        )[0]:
                            zip_and_zipfile_path = os.path.join(
                                file_path, os.path.relpath(extracted_file_path, extract_path)
                            )
                            local_file_metadata = pathlib.Path(extracted_file_path).stat()
                            file_size = local_file_metadata.st_size
                            # Get info from the pre-computed hash data if it is available
                            if zip_and_zipfile_path in pre_computed_hash_values:
                                file_metadata = get_metadata_from_precomputed(
                                    zip_and_zipfile_path,
                                    pre_computed_hash_values,
                                    file_size,
                                    source_folder,
                                    log,
                                )
                            else:
                                file_mtime = local_file_metadata.st_mtime
                                file_ctime = (
                                    file_mtime  # Generally after extract, only mtime is preserved
                                )
                                file_metadata = get_metadata_from_file(
                                    zip_and_zipfile_path,
                                    None,
                                    extracted_file_path,
                                    file_size,
                                    file_ctime,
                                    file_mtime,
                                    source_folder,
                                    hash_algorithms,
                                    preferred_hash_length,
                                )
                            if file_metadata.preferred_hash not in hashes:
                                hashes[file_metadata.preferred_hash] = []
                            write_metadata_line(file_metadata, OUTPUT_TEMPLATE, file_handler)
                            hashes[file_metadata.preferred_hash].append(file_metadata)
                    except FileNotFoundError:
                        log.warning(
                            "7z not found on PATH - extraction of '%s'%s cannot proceed",
                            file_path,
                            " (encrypted zip)" if file_extension == ".zip" else "",
                        )
                    except subprocess.CalledProcessError as error:
                        log.warning("Error occurred using 7z with: '%s'", file_path)
                        log.debug(error.output)
                    # Delete the files that were extracted from the archive and used for hashing
                    # Todo: do full clean of dirs in cache folder each iteration - otherwise empty
                    # source folders get left before final delete at end of hashing
                    try:
                        shutil.rmtree(extract_path, onerror=_apply_write_permissions)
                    except PermissionError:
                        log.warning(
                            "Permission error occurred when deleting extract folder '%s' - this"
                            " will need to be deleted manually",
                            extract_path,
                        )
    if archive_flag or only_archive_contents:
        if os.path.isdir(cache_path):
            try:
                shutil.rmtree(cache_path, onerror=_apply_write_permissions)
            except PermissionError:
                log.warning(
                    "Permission error occurred when deleting cache folder '%s' - this will need to"
                    " be deleted manually",
                    cache_path,
                )
    return hashes


def _hash_files_worker(
    file_paths: typing.List[str],
    parent_folder: str,
    source_or_destination_str: str,
    hash_algorithms: typing.List[str],
    preferred_algorithm: str,
    log_folder_path: str,
    log_queue: typing.Optional[multiprocessing.Queue],
    archives_flag: bool,
    only_archive_contents_flag: bool,
    cache_path: str,
    pre_computed_hash_values: typing.Dict[str, typing.Dict[str, typing.Any]],
    zip_password: typing.Optional[str] = None,
    process_number: int = 0,
) -> typing.Tuple[str, str, typing.Dict[str, typing.List[FileMetadata]],]:
    """Called as a separate process from the merge function; adds results of hashing of a folder
    to a Queue for review in the main thread

    """
    # Need to create the log object using a QueueHandler if running from a separate process
    log = logging.getLogger(__name__)
    try:
        hashes = hash_files(
            file_paths,
            parent_folder,
            source_or_destination_str,
            hash_algorithms,
            preferred_algorithm,
            log_folder_path,
            log_queue,
            archives_flag,
            only_archive_contents_flag,
            cache_path,
            pre_computed_hash_values,
            zip_password,
            process_number,
        )
    except:
        log.exception("Exception occurred in hash worker thread:")
        return ("", "", {})
    return (parent_folder, source_or_destination_str, hashes)


def _initialise_and_hash(
    source_paths: typing.List[str],
    destination_path: typing.Optional[str],
    run_time_str: str,
    log_folder_path: str,
    operation_type: str,
    hash_algorithms: typing.List[str],
    only_hash_copied_files: bool,
    hash_file_paths: typing.Optional[typing.List[str]],
    ignore_dotfiles: bool,
    ignore_windows_volume_folders: bool,
    archives_flag: bool = False,
    only_archive_contents_flag: bool = False,
    cache_path: str = "cache",
    zip_password: typing.Optional[str] = None,
) -> typing.Optional[
    typing.Tuple[
        typing.Dict[str, typing.List[FileMetadata]],
        typing.Dict[str, typing.List[FileMetadata]],
        int,
        str,
        typing.List[str],
        str,
    ]
]:
    """Run actions common to copy/move, merge, exchange, and hash operations"""
    log = logging.getLogger(__name__)
    # Check passed arguments and return if issues
    if get_missing_sources(source_paths):
        log.error(
            "Item(s) %s not found",
            get_list_as_str(get_missing_sources(source_paths)),
        )
        return None
    source_files = [os.path.abspath(path) for path in source_paths if os.path.isfile(path)]
    if operation_type == "exchange":
        if source_files:
            log.error(
                "Source path(s) %s are files - folder paths must be provided in exchange mode",
                get_list_as_str(source_files),
            )
            return None
        if len(source_paths) < 2:
            log.error("Two or more source paths must be provided")
            return None
    if destination_path is not None and operation_type != "hash":
        if os.path.isfile(destination_path):
            log.error(
                "Destination path must be a directory (either existing or to be created), not a"
                " file"
            )
            return None
    if archives_flag or only_archive_contents_flag:  # Will only be the case in 'hash' mode
        if os.path.isdir(cache_path):
            log.error(
                "Cache folder '%s' already exists - as this will be deleted at the end of the"
                " script, for safety, please provide a path that does not already exist",
                cache_path,
            )
            return None
    if hash_file_paths is not None:
        if get_missing_sources(hash_file_paths, files_only=True):
            log.error(
                "Hash file(s) %s not present",
                get_list_as_str(get_missing_sources(hash_file_paths)),
            )
            return None

    # Convert any relative paths to absolute (to ensure key lookups using source_path later on work)
    source_paths = [os.path.abspath(source_path) for source_path in source_paths]
    if destination_path is not None:
        destination_path = os.path.abspath(destination_path)

    # Confirm what we'll be doing
    source_paths_str = get_list_as_str(source_paths)
    if destination_path is not None and operation_type != "hash":
        # Create destination directory if it does not already exist
        pathlib.Path(destination_path).mkdir(parents=True, exist_ok=True)
        log.info(
            "Contents of source(s) %s will %s into destination '%s'",
            source_paths_str,
            operation_type,
            destination_path,
        )
    elif operation_type == "hash":
        log.info(
            "Contents of source(s) %s will be hashed%s",
            source_paths_str,
            " with final results unified into '{}'".format(destination_path)
            if destination_path is not None
            else "",
        )
    else:
        log.info("Contents of source(s) %s will be exchanged", source_paths_str)

    # Create log folder for this operation
    log_folder_subpath = os.path.join(log_folder_path, "{}_{}".format(run_time_str, operation_type))
    pathlib.Path(log_folder_subpath).mkdir(parents=True, exist_ok=True)

    # Get file paths and size metadata for each path
    source_folders = [os.path.abspath(path) for path in source_paths if os.path.isdir(path)]
    source_sizes = {}  # type: typing.Dict[str, int]
    for source_path in source_paths:
        source_sizes[source_path] = 0
    file_metadata_for_hash_workers = []
    source_total_size = 0
    for source_folder in source_folders:
        source_path_files, source_size = get_file_paths_and_total_size(
            [source_folder], ignore_dotfiles, ignore_windows_volume_folders
        )
        if source_path_files:
            file_metadata_for_hash_workers.append((source_path_files, source_folder, "source"))
        else:
            log.info("Source '%s' is empty", source_folder)
        source_total_size += source_size
        source_sizes[source_folder] += source_size
    for source_file in source_files:
        file_metadata_for_hash_workers.append(([source_file], source_file, "source"))
        source_total_size += os.path.getsize(source_file)
        source_sizes[source_file] += os.path.getsize(source_file)
    # Hash the destination if we're merging, or copying/moving and user has not opted to just hash
    # copied files
    if (
        destination_path is not None
        and operation_type != "hash"
        and operation_type != "exchange"
        and (operation_type == "merge" or not only_hash_copied_files)
    ):
        destination_files, _ = get_file_paths_and_total_size(
            [destination_path], ignore_dotfiles, ignore_windows_volume_folders
        )
        if destination_files:
            file_metadata_for_hash_workers.append(
                (destination_files, destination_path, "destination_before_copy")
            )
        else:
            log.info("Destination '%s' is empty", destination_path)
    # Advise if potential free space issue on merge/exchange; cancel entirely if insufficient free
    # space for copy/merge
    if destination_path is not None and operation_type != "hash":
        _, _, destination_free_space = shutil.disk_usage(destination_path)
        if destination_free_space < source_total_size:
            if operation_type == "merge":
                log.warning(
                    "Destination may not have enough disk space for data contained in source"
                    " folder(s) - destination has %s free space for %s total source files. Note"
                    " that not all data may need to be copied to the destination, so copy may still"
                    " complete without issue (an error will be generated after hashing if the copy"
                    " cannot proceed)",
                    bytes_filesize_to_readable_str(destination_free_space),
                    bytes_filesize_to_readable_str(source_total_size),
                )
            elif operation_type == "copy":
                log.error(
                    "Destination does not have enough disk space for data contained in source"
                    " folder(s) - destination has %s free space for %s total source files.",
                    bytes_filesize_to_readable_str(destination_free_space),
                    bytes_filesize_to_readable_str(source_total_size),
                )
                return None
    if operation_type == "exchange":
        for source_path in source_paths:
            _, _, source_free_space = shutil.disk_usage(source_path)
            other_source_paths = [path for path in source_paths if path != source_path]
            other_sources_total_size = sum(
                [size for (source, size) in source_sizes.items() if source != source_path]
            )
            if source_free_space < other_sources_total_size:
                log.warning(
                    "'%s' may not have enough disk space for data contained in folder(s) %s"
                    " - %s free space for %s total files to possibly be copied. Note"
                    " that not all data may need to be copied to the folder, so copy may still"
                    " complete without issue (an error will be generated after hashing if the copy"
                    " cannot proceed)",
                    source_path,
                    get_list_as_str(other_source_paths),
                    bytes_filesize_to_readable_str(source_free_space),
                    bytes_filesize_to_readable_str(other_sources_total_size),
                )

    process_count = len(source_paths) + 1
    hash_pool = multiprocessing.Pool(process_count, initializer=_hash_pool_initializer)
    log.info(
        "Commencing file hashing of source(s) paths%s",
        " and destination path"
        if operation_type == "merge" or (operation_type != "hash" and not only_hash_copied_files)
        else "",
    )
    # Setup log queue so workers can send updates to log
    manager = multiprocessing.Manager()
    log_queue = manager.Queue(-1)
    log_thread = threading.Thread(
        target=_log_listener,
        args=(log_queue,),
    )
    log_thread.setDaemon(True)
    log_thread.start()

    # Bring in pre-computed hash data if any have been provided
    pre_computed_hash_values = {}  # type: typing.Dict[str, typing.Dict[str, typing.Any]]
    # Helpfully, 'md5', 'sha1', and 'sha256' strings reverse sort into order of preference
    preferred_algorithm = sorted(hash_algorithms, reverse=True)[0]
    if hash_file_paths is not None:
        pre_computed_hash_values = get_dict_from_hash_files(hash_file_paths)
        if pre_computed_hash_values:
            # Confirm preferred algorithm - it's whichever is 'best' that also features across all
            # entries
            new_preferred_algorithm = ""
            for hash_algorithm in sorted(hash_algorithms, reverse=True):
                # Check if every pre-computed metadata item has a sha256/sha1/md5 value
                if all(
                    [
                        hash_algorithm in pre_computed_hash_values[path]
                        for path in pre_computed_hash_values.keys()
                    ]
                ):
                    new_preferred_algorithm = hash_algorithm
                    break
            if (
                new_preferred_algorithm == ""
            ):  # i.e. none of the user-specified algorithms are pre-computed
                # Get the best alternative available that's present in the pre-computed data
                for algorithm in ["sha256", "sha1", "md5"]:
                    if all(
                        [
                            algorithm in pre_computed_hash_values[path]
                            for path in pre_computed_hash_values.keys()
                        ]
                    ):
                        new_preferred_algorithm = algorithm
                        break
            if new_preferred_algorithm not in hash_algorithms:
                log.warning(
                    "Hash file(s) %s does not uniformly contain any of the hash algorithms"
                    " specified for calculation (specified algorithms were %s, but none of these"
                    " are present - the best possible option from what is available is %s). This"
                    " algorithm will be added to those being calculated",
                    get_list_as_str(hash_file_paths),
                    get_list_as_str(hash_algorithms),
                    preferred_algorithm,
                )
                hash_algorithms.append(new_preferred_algorithm)
            preferred_algorithm = new_preferred_algorithm
    # Todo: add checking if sources are on the same drive - if so, do not create separate processes,
    # to avoid IO bottlenecking the drive
    # Load hashing tasks into hash pool
    results = (
        []
    )  # type: typing.List[typing.Tuple[str, str, typing.Dict[str, typing.List[FileMetadata]]]]
    process_number = 0
    for file_paths, path, source_or_destination_str in file_metadata_for_hash_workers:
        hash_pool.starmap_async(
            _hash_files_worker,
            iterable=[
                (
                    file_paths,
                    path,
                    source_or_destination_str,
                    hash_algorithms,
                    preferred_algorithm,
                    log_folder_subpath,
                    log_queue,
                    archives_flag,
                    only_archive_contents_flag,
                    cache_path,
                    pre_computed_hash_values,
                    zip_password,
                    process_number,
                )
            ],
            callback=results.extend,
        )
        process_number += 1
    # Wait until file hashing complete
    hash_pool.close()
    hash_pool.join()  # Blocks until hashing processes are complete
    log.info("Hashing complete")
    log_queue.put_nowait(None)
    log_thread.join()
    source_hashes = {}

    # Transform data loaded per process into 'results' into unified dict 'destination_hashes'
    destination_hashes = {}
    for result in results:
        folder, source_or_destination_str, hashes = result
        if not hashes:
            log.error("Exception occurred in worker thread")
            return None
        log.info(
            "%s '%s' has %s unique hashes for %s files",
            source_or_destination_str.title().split("_")[0],
            folder,
            len(hashes),
            sum([len(metadata_list) for metadata_list in hashes.values()]),
        )
        if source_or_destination_str == "source":
            for hash_value, file_metadata_list in hashes.items():
                if hash_value not in source_hashes:
                    source_hashes[hash_value] = file_metadata_list
                else:
                    source_hashes[hash_value].extend(file_metadata_list)
        elif source_or_destination_str == "destination_before_copy":
            for hash_value, file_metadata_list in hashes.items():
                if hash_value not in destination_hashes:
                    destination_hashes[hash_value] = file_metadata_list
                else:
                    destination_hashes[hash_value].extend(file_metadata_list)

    if not source_hashes:
        log.error("No files found in any of the provided source(s)")
        return None

    to_be_copied_file_count = 0
    # Confirm whether sufficient free space available to proceed
    if operation_type != "hash" and operation_type != "exchange":
        required_free_space_on_destination = 0
        for hash_value, file_metadata_list in source_hashes.items():
            # Only count required space for 'merge' if we don't already have the file at destination
            if (
                operation_type == "copy" or operation_type == "move"
            ) or hash_value not in destination_hashes:
                for file_metadata in file_metadata_list:
                    required_free_space_on_destination += file_metadata.size
                    to_be_copied_file_count += 1
            else:
                # We're here if we're merging and we've already got the file in the destination
                # But we'll still need to create a .references.txt file, so allocate some space for
                # this - not an exact science but let's say 10KB for each file
                for _ in file_metadata_list:
                    required_free_space_on_destination += 10000
        if destination_free_space < required_free_space_on_destination:
            log.error(
                "Destination does not have enough free space for required files to be copied from"
                " source(s) - destination has %s free space for %s files to be copied from source.",
                bytes_filesize_to_readable_str(destination_free_space),
                bytes_filesize_to_readable_str(source_total_size),
            )
            return None
        if to_be_copied_file_count > 0:
            log.info(
                "%s files (%s) not present at the destination will be copied from source(s)",
                to_be_copied_file_count,
                bytes_filesize_to_readable_str(required_free_space_on_destination),
            )
        else:
            log.info(
                "All files on source(s) are already present on destination%s",
                " - .references.txt files will be"
                " created on destination to show locations of these files"
                if operation_type == "merge"
                else "",
            )
    if operation_type == "exchange":
        for source_path in source_paths:
            required_free_space_on_source = 0
            source_to_be_copied_file_count = 0
            other_source_paths = [path for path in source_paths if path != source_path]
            # Get set of all hashes from the master source set where one of the files with the hash
            # is present on the source path
            source_hashes_set = set(
                [
                    hash_value
                    for hash_value in source_hashes.keys()
                    if source_path in [meta.source_folder for meta in source_hashes[hash_value]]
                ]
            )
            # Get set of all hashes from the master source set where none of the files with the hash
            # are present on the source path
            other_hashes_set = set(
                [
                    hash_value
                    for hash_value in source_hashes.keys()
                    if source_path not in [meta.source_folder for meta in source_hashes[hash_value]]
                ]
            )
            for hash_value in other_hashes_set:
                for file_metadata in source_hashes[hash_value]:
                    required_free_space_on_source += file_metadata.size
                    source_to_be_copied_file_count += 1
            for hash_value in source_hashes_set:
                for _ in [
                    _ for meta in source_hashes[hash_value] if meta.source_folder != source_path
                ]:
                    # We're here if we're exchanging and we've already got the file in the source
                    # But we'll still need to create a .references.txt file, so allocate some space
                    # for this - not an exact science but let's say 10KB for each file
                    required_free_space_on_source += 10000
            _, _, source_free_space = shutil.disk_usage(source_path)
            if source_free_space < required_free_space_on_source:
                log.error(
                    "'%s' does not have enough disk space for data contained in folder(s) %s"
                    " - %s free space for %s total files to possibly be copied. Note"
                    " that not all data may need to be copied to the folder, so copy may still"
                    " complete without issue (an error will be generated after hashing if the copy"
                    " cannot proceed)",
                    source_path,
                    get_list_as_str(other_source_paths),
                    bytes_filesize_to_readable_str(source_free_space),
                    bytes_filesize_to_readable_str(required_free_space_on_source),
                )
                return None
            to_be_copied_file_count += source_to_be_copied_file_count

    return (
        source_hashes,
        destination_hashes,
        to_be_copied_file_count,
        log_folder_subpath,
        hash_algorithms,
        preferred_algorithm,
    )


def _check_finalised_hashes(
    destination_path: str,
    updated_dest_hashes: typing.Dict[str, typing.List[FileMetadata]],
    source_hashes_to_verify_against: typing.Set[str],
    source_hashes: typing.Dict[str, typing.List[FileMetadata]],
    copied_file_metadata: typing.Dict[str, str],
) -> bool:
    log = logging.getLogger(__name__)
    if (
        # If all our source hashes can be found in the updated destination hashes
        all(hash_value in updated_dest_hashes for hash_value in source_hashes_to_verify_against)
        # And all expected files exist
        and all(os.path.isfile(copied_file) for copied_file in copied_file_metadata.keys())
        # And all expected hashes can be found in the new hashes data, and the expected file
        # paths for these hashes are all present
        and all(
            copied_file_metadata[copied_file] in updated_dest_hashes
            and copied_file
            in [meta.path for meta in updated_dest_hashes[copied_file_metadata[copied_file]]]
            for copied_file in copied_file_metadata.keys()
        )
    ):
        return True
    else:
        for hash_value in source_hashes_to_verify_against:
            if hash_value not in updated_dest_hashes:
                log.error(
                    "%s not found in destination '%s' (files: %s)",
                    hash_value,
                    destination_path,
                    get_list_as_str([meta.path for meta in source_hashes[hash_value]]),
                )
        for copied_file, expected_hash in copied_file_metadata.items():
            if not os.path.isfile(copied_file):
                log.error(
                    "Expected file '%s' does not exist in destination '%s'",
                    copied_file,
                    destination_path,
                )
            if (expected_hash not in updated_dest_hashes) or (
                copied_file not in [meta.path for meta in updated_dest_hashes[expected_hash]]
            ):
                log.error(
                    "Hash for file '%s' ('%s') not found in verification data for destination '%s'",
                    copied_file,
                    expected_hash,
                    destination_path,
                )
        return False


def copy_or_move_mode(
    copy: bool,  # True is copy, False is move
    source_paths: typing.List[str],
    destination_path: str,
    run_time_str: str,
    log_folder_path: str,
    only_hash_copied_files: bool,
    hash_file_paths: typing.Optional[typing.List[str]],
    hash_algorithms: typing.List[str],
    ignore_dotfiles: bool,
    ignore_windows_volume_folders: bool,
) -> None:
    """Copy/move files from source path(s) into destination path with hash verification pre and post
    transfer

    """
    log = logging.getLogger(__name__)
    # Check arguments and get hash data
    initialise_result = _initialise_and_hash(
        source_paths,
        destination_path,
        run_time_str,
        log_folder_path,
        "copy" if copy else "move",
        hash_algorithms,
        only_hash_copied_files,
        hash_file_paths,
        ignore_dotfiles,
        ignore_windows_volume_folders,
    )
    if initialise_result is None:  # i.e. exception or error occurred
        return
    else:
        (
            source_hashes,
            _,
            to_be_copied_file_count,
            log_folder_subpath,
            hash_algorithms,
            preferred_algorithm,
        ) = initialise_result
    source_paths_str = get_list_as_str(source_paths)

    if len(source_paths) > 1:
        log.info(
            "As multiple sources were provided, data will %s into subfolder(s) in destination '%s',"
            " to ensure no filename conflicts between sources",
            "copy" if copy else "move",
            destination_path,
        )

    source_file_paths = []
    copied_file_metadata = {}
    with tqdm.tqdm(total=to_be_copied_file_count) as progress_bar:
        for hash_value, file_metadata_list in source_hashes.items():
            for file_metadata in file_metadata_list:
                # If source was a file, its folder will have been set at the full file path, to
                # allow logging to correct location in hash worker. So let's reset it to its parent
                # folder
                if os.path.isfile(file_metadata.source_folder):
                    file_metadata.source_folder = os.path.dirname(file_metadata.source_folder)
                rel_path = os.path.relpath(file_metadata.path, file_metadata.source_folder)
                # If we have multiple sources, give them their own folder on the destination, to
                # ensure no filename conflicts
                if len(source_paths) > 1:
                    destination_subfolder_path = os.path.join(
                        destination_path, get_safe_path_name(file_metadata.source_folder)
                    )
                else:
                    destination_subfolder_path = destination_path
                dest_file_path = os.path.join(destination_subfolder_path, rel_path)
                pathlib.Path(os.path.dirname(dest_file_path)).mkdir(parents=True, exist_ok=True)
                if os.path.isfile(dest_file_path):
                    dest_file_size = os.path.getsize(dest_file_path)
                    # If file size suggests a file already at the destination isn't our intended
                    # file (perhaps from a previous copy), warn and rename our output path
                    if dest_file_size != file_metadata.size:
                        dest_file_path_rename = get_unused_output_path(dest_file_path)
                        log.warning(
                            "File '%s' already exists at '%s' but with incorrect file size (%s on"
                            " source, %s on destination) - file will be copied with renamed"
                            " filename '%s",
                            file_metadata.path,
                            dest_file_path,
                            file_metadata.size,
                            dest_file_size,
                            os.path.basename(dest_file_path_rename),
                        )
                        dest_file_path = dest_file_path_rename
                    else:
                        copied_file_metadata[dest_file_path] = hash_value
                        source_file_paths.append(file_metadata.path)
                        progress_bar.update()
                        continue  # Not rehashing here as will hash when all other files copied
                log.debug("Copying '%s' to '%s'", file_metadata.path, dest_file_path)
                shutil.copy2(file_metadata.path, dest_file_path)
                copied_file_metadata[dest_file_path] = hash_value
                source_file_paths.append(file_metadata.path)
                progress_bar.update()

    log.info(
        "Copying complete - now will verify %s in destination '%s'",
        "copied files only" if only_hash_copied_files else "all data",
        destination_path,
    )
    # If hashing just copied files, we're just hashing the file copies we've tracked in
    # copied_file_metadata rather than the full destination
    if only_hash_copied_files:
        updated_dest_hashes = hash_files(
            sorted(list(copied_file_metadata.keys())),
            destination_path,
            "files_copied_to_destination",
            hash_algorithms,
            preferred_algorithm,
            log_folder_subpath,
        )
    else:  # Otherwise, re-hash the whole destination path
        updated_dest_file_paths, _ = get_file_paths_and_total_size(
            [destination_path], ignore_dotfiles, ignore_windows_volume_folders
        )
        updated_dest_hashes = hash_files(
            updated_dest_file_paths,
            destination_path,
            "destination_after_copy",
            hash_algorithms,
            preferred_algorithm,
            log_folder_subpath,
        )
    if _check_finalised_hashes(
        destination_path,
        updated_dest_hashes,
        set(source_hashes.keys()),
        source_hashes,
        copied_file_metadata,
    ):
        log.info(
            "Confirmed all files copied from %s to '%s' successfully",
            source_paths_str,
            destination_path,
        )
        # If confirmed data is as expected and we're moving files, delete the source paths
        if not copy:  # i.e. 'move'
            log.info("All data verified as moved OK - will now delete files in source folder(s)")
            source_folders = [os.path.abspath(path) for path in source_paths if os.path.isdir(path)]
            # Delete files from source(s) that have been copied
            for source_file in source_file_paths:
                log.debug("Deleting '%s'", source_file)
                try:
                    os.remove(source_file)
                except PermissionError:
                    log.warning(
                        "Permission error occurred when deleting source file '%s' - this will need"
                        " to be deleted manually",
                        source_file,
                    )
            # If folders are now empty, delete those too
            for source_folder in source_folders:
                try:
                    if not os.listdir(source_folder):
                        log.debug("Deleting empty folder '%s'", source_folder)
                        shutil.rmtree(source_folder)
                    else:
                        log.info(
                            "Source folder '%s' is not empty, so has not been deleted as part of"
                            " move",
                            source_folder,
                        )
                except PermissionError:
                    log.warning(
                        "Permission error occurred when deleting source folder '%s' - this will"
                        " need to be deleted manually",
                        source_folder,
                    )
    else:
        log.warning("Not all files were verified successfully (see warnings above)")


def merge_mode(
    source_paths: typing.List[str],
    destination_path: str,
    run_time_str: str,
    log_folder_path: str,
    only_hash_copied_files: bool,
    hash_file_paths: typing.Optional[typing.List[str]],
    hash_algorithms: typing.List[str],
    ignore_dotfiles: bool,
    ignore_windows_volume_folders: bool,
) -> None:
    """Merge files from source path(s) into destination path - files will only be copied from source
    to destination if the file does not already exist on the destination at some location

    """
    log = logging.getLogger(__name__)
    # Check arguments and get hash data
    initialise_result = _initialise_and_hash(
        source_paths,
        destination_path,
        run_time_str,
        log_folder_path,
        "merge",
        hash_algorithms,
        only_hash_copied_files,
        hash_file_paths,
        ignore_dotfiles,
        ignore_windows_volume_folders,
    )
    if initialise_result is None:  # i.e. exception or error occurred
        return
    else:
        (
            source_hashes,
            destination_hashes,
            to_be_copied_file_count,
            log_folder_subpath,
            hash_algorithms,
            preferred_algorithm,
        ) = initialise_result
    source_paths_str = get_list_as_str(source_paths)

    # Create merge folders on destination
    merge_folder = os.path.join(destination_path, "{}_merge".format(run_time_str))
    references_folder = os.path.join(merge_folder, "merge_hash_references")
    pathlib.Path(os.path.dirname(references_folder)).mkdir(parents=True, exist_ok=True)

    # Copy files that were only present on the source(s) and not the destination, and for shared
    # files that are already present on the source, write references files
    with tqdm.tqdm(total=to_be_copied_file_count) as progress_bar:
        copied_file_metadata = {}
        for hash_value, file_metadata_list in source_hashes.items():
            if hash_value not in destination_hashes:
                log.debug(
                    "%s does not exist in destination; file(s) %s will be copied",
                    hash_value,
                    get_list_as_str([meta.path for meta in file_metadata_list]),
                )
                for file_metadata in file_metadata_list:
                    # If source was a file, its folder will have been set at the full file path, to
                    # allow logging to correct location in hash worker. So let's reset it to its
                    # parent folder
                    if os.path.isfile(file_metadata.source_folder):
                        file_metadata.source_folder = os.path.dirname(file_metadata.source_folder)
                    rel_path = os.path.relpath(file_metadata.path, file_metadata.source_folder)
                    merge_subfolder_path = os.path.join(
                        merge_folder, get_safe_path_name(file_metadata.source_folder)
                    )
                    dest_file_path = os.path.join(merge_subfolder_path, rel_path)
                    pathlib.Path(os.path.dirname(dest_file_path)).mkdir(parents=True, exist_ok=True)
                    log.debug("Copying '%s' to '%s'", file_metadata.path, dest_file_path)
                    # Not checking if file already exists as files will be in a dedicated subfolder
                    # with a timestamp of script execution - i.e. no reason why there would be
                    # conflicts
                    shutil.copy2(file_metadata.path, dest_file_path)
                    copied_file_metadata[dest_file_path] = hash_value
                    progress_bar.update()
            else:
                log.debug(
                    "%s exists in destination (source file(s) %s, destination file(s) %s)",
                    hash_value,
                    get_list_as_str([meta.path for meta in file_metadata_list]),
                    get_list_as_str([meta.path for meta in destination_hashes[hash_value]]),
                )
                for file_metadata in file_metadata_list:
                    # If source was a file, its folder will have been set at the full file path, to
                    # allow logging to correct location in hash worker. So let's reset it to its
                    # parent folder
                    if os.path.isfile(file_metadata.source_folder):
                        file_metadata.source_folder = os.path.dirname(file_metadata.source_folder)
                    rel_path = os.path.relpath(file_metadata.path, file_metadata.source_folder)
                    references_subfolder_path = os.path.join(
                        references_folder, get_safe_path_name(file_metadata.source_folder)
                    )
                    # Create '.references.txt' for files that already existed on destination
                    dest_file_path = "{}.references.txt".format(
                        os.path.join(references_subfolder_path, rel_path)
                    )
                    pathlib.Path(os.path.dirname(dest_file_path)).mkdir(parents=True, exist_ok=True)
                    with open(
                        dest_file_path, "w", encoding="utf-8", errors="ignore"
                    ) as file_handler:
                        file_handler.write(
                            "\n".join([meta.path for meta in destination_hashes[hash_value]])
                        )

    log.info(
        "Copying complete - now will verify %s in destination '%s'",
        "copied files in merge folder '{}'".format(merge_folder)
        if only_hash_copied_files
        else "all data",
        destination_path,
    )
    # If flagged to only hash copied files, just hash contents of the merge folder, which will be
    # extent of all new files copied to destination
    if only_hash_copied_files:
        updated_dest_file_paths, _ = get_file_paths_and_total_size(
            [merge_folder], ignore_dotfiles, ignore_windows_volume_folders
        )
        updated_dest_hashes = hash_files(
            updated_dest_file_paths,
            destination_path,
            "merge_folder_on_destination_after_copy",
            hash_algorithms,
            preferred_algorithm,
            log_folder_subpath,
        )
        # If hashing just copied files, we're just hashing the merge folder on the destination, so
        # remove from consideration any files outside that folder that may exist on other sources
        source_hashes_to_verify_against = source_hashes.keys() - destination_hashes.keys()
    else:  # Otherwise, re-hash everything
        updated_dest_file_paths, _ = get_file_paths_and_total_size(
            [destination_path], ignore_dotfiles, ignore_windows_volume_folders
        )
        updated_dest_hashes = hash_files(
            updated_dest_file_paths,
            destination_path,
            "destination_after_copy",
            hash_algorithms,
            preferred_algorithm,
            log_folder_subpath,
        )
        # As rehashing everything, compare against all the original hashes across all the sources
        source_hashes_to_verify_against = set(source_hashes.keys())
    if _check_finalised_hashes(
        destination_path,
        updated_dest_hashes,
        source_hashes_to_verify_against,
        source_hashes,
        copied_file_metadata,
    ):
        log.info(
            "Confirmed all files not previously present on '%s' copied from %s to '%s'"
            " successfully",
            destination_path,
            source_paths_str,
            merge_folder,
        )
    else:
        log.warning("Not all files were verified successfully (see warnings above)")


def exchange_mode(
    source_paths: typing.List[str],
    run_time_str: str,
    log_folder_path: str,
    only_hash_copied_files: bool,
    hash_file_paths: typing.Optional[typing.List[str]],
    hash_algorithms: typing.List[str],
    ignore_dotfiles: bool,
    ignore_windows_volume_folders: bool,
) -> None:
    """Exchange files between source paths - files will only be copied from source
    to destination if the file does not already exist on the destination at some location

    """
    log = logging.getLogger(__name__)
    # Check arguments and get hash data
    initialise_result = _initialise_and_hash(
        source_paths,
        None,  # destination_path
        run_time_str,
        log_folder_path,
        "exchange",
        hash_algorithms,
        only_hash_copied_files,
        hash_file_paths,
        ignore_dotfiles,
        ignore_windows_volume_folders,
    )
    if initialise_result is None:  # i.e. exception or error occurred
        return
    else:
        (
            source_hashes,
            _,
            to_be_copied_file_count,
            log_folder_subpath,
            hash_algorithms,
            preferred_algorithm,
        ) = initialise_result

    # Convert any relative paths to absolute (to ensure key lookups using source_path later on work)
    source_paths = [os.path.abspath(source_path) for source_path in source_paths]

    # Create exchange folders on each source
    for source_path in source_paths:
        exchange_folder = os.path.join(source_path, "{}_exchange".format(run_time_str))
        references_folder = os.path.join(exchange_folder, "exchange_hash_references")
        pathlib.Path(os.path.dirname(references_folder)).mkdir(parents=True, exist_ok=True)

    # Per source, copy files that were only present on other sources, and for shared files that are
    # already present on the source, write references files
    copied_file_metadata = {}
    with tqdm.tqdm(total=to_be_copied_file_count) as progress_bar:
        for source_path in source_paths:
            exchange_folder = os.path.join(source_path, "{}_exchange".format(run_time_str))
            references_folder = os.path.join(exchange_folder, "exchange_hash_references")
            source_copied_file_metadata = {}  # Master tracker of copied file details
            copied_file_metadata[source_path] = source_copied_file_metadata  # Per-source tracker
            other_source_paths = [path for path in source_paths if path != source_path]
            for hash_value, file_metadata_list in source_hashes.items():
                source_folders_containing_hash_value = set(
                    [meta.source_folder for meta in file_metadata_list]
                )
                # If no files with the hash_value are located on this source_path, need to copy
                if source_path not in source_folders_containing_hash_value:
                    log.debug(
                        "%s does not exist in source '%s'; file(s) %s will be copied",
                        hash_value,
                        source_path,
                        get_list_as_str([meta.path for meta in source_hashes[hash_value]]),
                    )
                    for file_metadata in file_metadata_list:
                        # If source was a file, its folder will have been set at the full file path,
                        # to allow logging to correct location in hash worker. So let's reset it to
                        # its parent folder
                        if os.path.isfile(file_metadata.source_folder):
                            file_metadata.source_folder = os.path.dirname(
                                file_metadata.source_folder
                            )
                        rel_path = os.path.relpath(file_metadata.path, file_metadata.source_folder)
                        exchange_subfolder_path = os.path.join(
                            exchange_folder, get_safe_path_name(file_metadata.source_folder)
                        )
                        dest_file_path = os.path.join(exchange_subfolder_path, rel_path)
                        pathlib.Path(os.path.dirname(dest_file_path)).mkdir(
                            parents=True, exist_ok=True
                        )
                        log.debug("Copying '%s' to '%s'", file_metadata.path, dest_file_path)
                        # Not checking if file already exists as files will be in a dedicated
                        # subfolder with a timestamp of script execution - i.e. no reason why there
                        # would be conflicts
                        shutil.copy2(file_metadata.path, dest_file_path)
                        source_copied_file_metadata[dest_file_path] = hash_value
                        progress_bar.update()
                # If the hash_value was present somewhere on source, just write references files
                else:
                    source_filepaths = [
                        meta.path
                        for meta in source_hashes[hash_value]
                        if meta.source_folder == source_path
                    ]
                    other_filepaths = [
                        (meta.path, meta.source_folder)
                        for meta in source_hashes[hash_value]
                        if meta.source_folder != source_path
                    ]
                    if not other_filepaths:  # If file doesn't exist outside this source, skip
                        continue
                    log.debug(
                        "%s on source '%s' exists on other sources (source filepath(s): %s -- other"
                        " source filepaths(s): %s)",
                        hash_value,
                        source_path,
                        get_list_as_str(source_filepaths),
                        get_list_as_str([x[0] for x in other_filepaths]),
                    )
                    for source_file_path, source_folder in other_filepaths:
                        # If source was a file, its folder will have been set at the full file path,
                        # to allow logging to correct location in hash worker. So let's reset it to
                        # its parent folder
                        if os.path.isfile(source_folder):
                            source_folder = os.path.dirname(source_folder)
                        rel_path = os.path.relpath(source_file_path, source_folder)
                        references_subfolder_path = os.path.join(
                            references_folder, get_safe_path_name(source_folder)
                        )
                        # Create '.references.txt' for files that already existed on source
                        dest_file_path = "{}.references.txt".format(
                            os.path.join(references_subfolder_path, rel_path)
                        )
                        pathlib.Path(os.path.dirname(dest_file_path)).mkdir(
                            parents=True, exist_ok=True
                        )
                        with open(
                            dest_file_path, "w", encoding="utf-8", errors="ignore"
                        ) as file_handler:
                            file_handler.write("\n".join(source_filepaths))
    log.info(
        "Copying complete - now will verify %s",
        "copied files in exchange folders" if only_hash_copied_files else "all source data",
    )
    # Run hashing as separate processes
    process_count = len(source_paths) + 1
    hash_pool = multiprocessing.Pool(process_count, initializer=_hash_pool_initializer)
    # Setup log queue so workers can send updates to log
    manager = multiprocessing.Manager()
    log_queue = manager.Queue(-1)
    log_thread = threading.Thread(
        target=_log_listener,
        args=(log_queue,),
    )
    log_thread.setDaemon(True)
    log_thread.start()

    # Load hashing tasks per source into hash pool
    results = []
    process_number = 0
    for source_path in source_paths:
        exchange_folder = os.path.join(source_path, "{}_exchange".format(run_time_str))
        # If flagged to only hash copied files, just hash contents of the exchange folder, which
        # will be extent of all new files copied to source
        if only_hash_copied_files:
            updated_dest_file_paths, _ = get_file_paths_and_total_size(
                [exchange_folder], ignore_dotfiles, ignore_windows_volume_folders
            )
        else:  # Otherwise, re-hash everything
            updated_dest_file_paths, _ = get_file_paths_and_total_size(
                [source_path], ignore_dotfiles, ignore_windows_volume_folders
            )
        hash_pool.starmap_async(
            _hash_files_worker,
            iterable=[
                (
                    updated_dest_file_paths,
                    source_path,
                    "source_after_exchange",
                    hash_algorithms,
                    preferred_algorithm,
                    log_folder_subpath,
                    log_queue,
                    False,  # archives_flag
                    False,  # only_archive_contents_flag
                    "",  # cache_path
                    {},  # pre_computed_hash_values
                    None,  # zip_password
                    process_number,
                )
            ],
            callback=results.extend,
        )
        process_number += 1
    # Wait until file hashing complete
    hash_pool.close()
    hash_pool.join()  # Blocks until hashing processes are complete
    log.info("Hashing complete")
    log_queue.put_nowait(None)
    log_thread.join()

    # Transform data loaded per process into 'results' into unified dict 'updated_source_hashes'
    updated_source_hashes = {}
    for result in results:
        updated_hashes = result[2]
        if not updated_hashes:
            log.error("Exception occurred in worker thread")
            return None
        for hash_value, file_metadata_list in updated_hashes.items():
            if hash_value not in updated_source_hashes:
                updated_source_hashes[hash_value] = file_metadata_list
            else:
                updated_source_hashes[hash_value].extend(file_metadata_list)

    for source_path in source_paths:
        exchange_folder = os.path.join(source_path, "{}_exchange".format(run_time_str))
        other_source_paths = [path for path in source_paths if path != source_path]
        # Hash details for files not originally found on this source_path
        other_hashes_set = set(
            [
                hash_value
                for hash_value in source_hashes.keys()
                if source_path not in [meta.source_folder for meta in source_hashes[hash_value]]
            ]
        )
        # Hash details for original state of source_path
        source_original_hashes_set = set(
            [
                hash_value
                for hash_value in source_hashes.keys()
                if source_path in [meta.source_folder for meta in source_hashes[hash_value]]
            ]
        )
        # If hashing just copied files, we're just hashing the exchange folder on the source, so
        # remove from consideration any files outside that folder that may exist on other sources
        if only_hash_copied_files:
            source_hashes_to_verify_against = other_hashes_set - source_original_hashes_set
        else:  # Otherwise, compare against all the original hashes across all the sources
            source_hashes_to_verify_against = set(source_hashes.keys())

        # Hash details for updated state of source_path
        source_updated_hashes_filtered = {
            hash: metadata_list
            for hash, metadata_list in updated_source_hashes.items()
            if source_path in [meta.source_folder for meta in metadata_list]
        }

        if _check_finalised_hashes(
            source_path,
            source_updated_hashes_filtered,
            source_hashes_to_verify_against,
            source_hashes,
            copied_file_metadata[source_path],
        ):
            log.info(
                "Confirmed all files not previously present on '%s' copied from %s to '%s'"
                " successfully",
                source_path,
                get_list_as_str(other_source_paths),
                exchange_folder,
            )
        else:
            log.warning("Not all files were verified successfully (see warnings above)")


def hash_mode(
    source_paths: typing.List[str],
    output_path: typing.Optional[str],
    run_time_str: str,
    log_folder_path: str,
    archives_flag: bool,
    only_archive_contents_flag: bool,
    cache_path: str,
    zip_password: typing.Optional[str],
    hash_algorithms: typing.List[str],
    ignore_dotfiles: bool,
    ignore_windows_volume_folders: bool,
) -> None:
    """Hash list of files, including files within .zip and .7z files if zip_flag is set"""
    log = logging.getLogger(__name__)
    # Check arguments and get hash data
    initialise_result = _initialise_and_hash(
        source_paths,
        output_path,
        run_time_str,
        log_folder_path,
        "hash",
        hash_algorithms,
        False,  # only_hash_copied files
        None,  # hash_file_paths
        ignore_dotfiles,
        ignore_windows_volume_folders,
        archives_flag,
        only_archive_contents_flag,
        cache_path,
        zip_password,
    )
    if initialise_result is None:  # i.e. exception or error occurred
        return
    else:
        source_hashes, _, _, _, _, _ = initialise_result

    # Get unified sorted list of hashes for final output
    if output_path is not None:
        file_listing = []
        for _, file_metadata_list in source_hashes.items():
            for file_metadata in file_metadata_list:
                file_listing.append(
                    (
                        file_metadata.hash_values,
                        file_metadata.path,
                        file_metadata.size,
                        file_metadata.ctime,
                        file_metadata.mtime,
                    )
                )
        file_listing.sort(key=operator.itemgetter(1))  # Sort by filepath
        with open(output_path, "w", encoding="utf-8", errors="ignore") as file_handler:
            for file_details in file_listing:
                file_handler.write(
                    "{}|{}|{}|{}|{}\n".format("|".join(file_details[0]), *file_details[1:])
                )
        log.info(
            "Unified hash file outputted to '%s' (per-source log files also present in log folder)",
            output_path,
        )


def compare_mode(
    source_file_path: str,
    dest_file_path: str,
    missing_files_output_path: typing.Optional[str],
    copy_missing_files_path: typing.Optional[str],
    compare_filepaths: bool,
) -> None:
    """Compare a source metadata file to see if all hashes are present in destination file"""
    log = logging.getLogger(__name__)

    if get_missing_sources([source_file_path, dest_file_path], files_only=True):
        log.error(
            "Item(s) %s not found",
            get_list_as_str(get_missing_sources([source_file_path, dest_file_path])),
        )
        return

    # Bring in metadata from hash files
    source_hash_values = get_dict_from_hash_files([source_file_path])
    dest_hash_values = get_dict_from_hash_files([dest_file_path])

    if not source_hash_values or not dest_hash_values:
        return None

    # Find a common hashing algorithm between the two files
    preferred_algorithm = ""
    for algorithm in ["sha256", "sha1", "md5"]:
        if all(
            [algorithm in source_hash_values[path] for path in source_hash_values.keys()]
        ) and all([algorithm in dest_hash_values[path] for path in dest_hash_values.keys()]):
            preferred_algorithm = algorithm
            break
    if preferred_algorithm == "":
        log.error(
            "No common hash algorithm was found between files '%s' and '%s' - cannot proceed",
            source_file_path,
            dest_file_path,
        )
        return

    # Build new dict source_metadata with preferred hash as key
    source_metadata = {}  # type: typing.Dict[str, typing.List[str]]
    for file_path, metadata in source_hash_values.items():
        if metadata[preferred_algorithm] not in source_metadata:
            source_metadata[metadata[preferred_algorithm]] = []
        source_metadata[metadata[preferred_algorithm]].append(file_path)
    dest_metadata = {}  # type: typing.Dict[str, typing.List[str]]
    for file_path, metadata in dest_hash_values.items():
        if metadata[preferred_algorithm] not in dest_metadata:
            dest_metadata[metadata[preferred_algorithm]] = []
        dest_metadata[metadata[preferred_algorithm]].append(file_path)

    # If every hash in the source file can be found in the destination file:
    if source_metadata.keys() <= dest_metadata.keys():
        log.info(
            "All hashes referenced in '%s' are present in '%s'",
            source_file_path,
            dest_file_path,
        )
    else:
        log.warning(
            "NOT all hashes referenced in '%s' are present in '%s'",
            source_file_path,
            dest_file_path,
        )
    missing_file_paths = []
    # Todo: order warning logs with missing hashes first, missing paths second
    for hash_value, file_paths in source_metadata.items():
        file_paths_str = get_list_as_str(file_paths)
        if hash_value in dest_metadata:
            if compare_filepaths:  # Also check that files are in the expected locations
                source_file_path_set = set(file_paths)
                dest_file_path_set = set(dest_metadata[hash_value])
                if source_file_path_set <= dest_file_path_set:
                    log.debug("All source file paths for %s found in destination", hash_value)
                else:
                    for source_file_path in sorted(list(source_file_path_set)):
                        if source_file_path not in dest_file_path_set:
                            log.warning(
                                "'%s' not present in destination output, however its hash %s still"
                                " exists as files %s",
                                source_file_path,
                                hash_value,
                                get_list_as_str(sorted(list(dest_file_path_set))),
                            )
        else:
            log.warning("%s (%s) not present in destination output", hash_value, file_paths_str)
            if copy_missing_files_path is not None:
                if len(file_paths) > 1:
                    log.warning(
                        "For missing file copy for %s, note more than one file with this hash"
                        " exists on source: %s",
                        hash_value,
                        file_paths_str,
                    )
                if os.path.isfile(file_paths[0]):
                    pathlib.Path(copy_missing_files_path).mkdir(parents=True, exist_ok=True)
                    copied_file_path = os.path.join(
                        copy_missing_files_path, os.path.basename(file_paths[0])
                    )
                    # Get a safe path to copy to if the destination file already exists
                    if os.path.isfile(copied_file_path):
                        copied_file_path = get_unused_output_path(copied_file_path)
                        log.warning(
                            "Missing file '%s' will be copied with filename '%s' as a file already "
                            "exists in '%s' with filename '%s'",
                            file_paths[0],
                            os.path.basename(copied_file_path),
                            copy_missing_files_path,
                            os.path.basename(file_paths[0]),
                        )
                    shutil.copy2(file_paths[0], copied_file_path)
                else:
                    log.warning(
                        "File '%s' does not exist to copy to '%s'",
                        file_paths[0],
                        copy_missing_files_path,
                    )
            missing_file_paths.extend(file_paths)
    if missing_files_output_path is not None:
        with open(
            missing_files_output_path, "w", encoding="utf-8", errors="ignore"
        ) as file_handler:
            for missing_file_path in sorted(missing_file_paths):
                file_handler.write("{}\n".format(missing_file_path))


def main() -> None:
    """Captures args via argparse and sets up a vericopy task"""
    run_time = datetime.datetime.now()
    datetime_string = run_time.strftime("%Y%m%d_%H%M%S")

    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        "-l",
        "--log",
        action="store_true",
        help=(
            "Write log files (will be written to folder 'vericopy_logs' if alternate path not"
            " specified with --logfolder)"
        ),
    )
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Show debug log entries in console and write to separate log file in log folder",
    )
    parser.add_argument(
        "--logfolder",
        default="vericopy_logs",
        help=(
            "Folder to write logs to (if not specified, folder 'vericopy_logs' will be used in"
            " same directory as this script)"
        ),
    )
    parser.add_argument(
        "--algorithms",
        type=str.lower,
        nargs="+",
        default=["sha1"],
        choices=["md5", "sha1", "sha256"],
        help="Hash algorithm(s) to use (sha1 is default) - options are 'md5', 'sha1' and 'sha256')",
    )
    parser.add_argument(
        "--ignore-dotfiles",
        action="store_true",
        help="Ignore files and folders beginning with '.' (typically these are hidden folders)",
    )
    parser.add_argument(
        "--ignore-windows-volume-folders",
        action="store_true",
        help=(
            "Ignore folders named 'System Volume Information' and '$RECYCLE.BIN' (typically these"
            " contain hidden system information)"
        ),
    )
    # Todo: add 'no multiprocessing' flag

    subparsers = parser.add_subparsers(
        help="Available commands: copy, move, merge, exchange, hash, compare",
        dest="command",
        required=True,
    )

    copy_parser = subparsers.add_parser("copy")
    copy_parser.add_argument(
        "source_paths",
        type=str,
        nargs="+",
        help="File or folder path(s) containing data to copy to destination",
    )
    # Todo: add support for multiple destination paths
    copy_parser.add_argument("destination_path", type=str, help="Destination path to copy data to")
    copy_parser.add_argument(
        "--only-hash-transferred-files",
        action="store_true",
        help="Flag to only hash copied files and not the whole destination path",
    )
    copy_parser.add_argument(
        # Todo: add support for ingesting folders of hash files
        "--hash-files",
        type=str,
        nargs="+",
        help=(
            "Pre-computed hash files that can be used in place of calculating hash data prior to"
            " copy"
        ),
    )

    move_parser = subparsers.add_parser("move")
    move_parser.add_argument(
        "source_paths",
        type=str,
        nargs="+",
        help="File or folder path(s) containing data to move to destination",
    )
    # Todo: add support for multiple destination paths
    move_parser.add_argument("destination_path", type=str, help="Destination path to copy data to")
    move_parser.add_argument(
        "--only-hash-transferred-files",
        action="store_true",
        help="Flag to only hash moved files and not the whole destination path",
    )
    move_parser.add_argument(
        # Todo: add support for ingesting folders of hash files
        "--hash-files",
        type=str,
        nargs="+",
        help=(
            "Pre-computed hash files that can be used in place of calculating hash data prior to"
            " move"
        ),
    )

    merge_parser = subparsers.add_parser("merge")
    merge_parser.add_argument(
        "source_paths",
        type=str,
        nargs="+",
        help="File or folder path(s) containing data to merge into destination",
    )
    # Todo: add support for multiple destination paths
    merge_parser.add_argument(
        "destination_path", type=str, help="Destination path to merge data into"
    )
    merge_parser.add_argument(
        "--only-hash-transferred-files",
        action="store_true",
        help="Flag to only hash merged files and not the whole destination path",
    )
    merge_parser.add_argument(
        # Todo: add support for ingesting folders of hash files
        "--hash-files",
        type=str,
        nargs="+",
        help=(
            "Pre-computed hash files that can be used in place of calculating hash data prior to"
            " merge"
        ),
    )
    # Todo: add option to merge to root folder, rather than creating 'merge' subfolder
    # Todo: for files to be merged that share a hash, have an option to only copy one instance
    # Todo: experiment with symlinks to see if they can replace ".references.txt" files

    exchange_parser = subparsers.add_parser("exchange")
    exchange_parser.add_argument(
        "source_paths",
        type=str,
        nargs="+",
        help="Folder path(s) containing data to exchange between",
    )
    exchange_parser.add_argument(
        "--only-hash-transferred-files",
        action="store_true",
        help="Flag to only hash exchanged files and not the whole destination path",
    )
    exchange_parser.add_argument(
        # Todo: add support for ingesting folders of hash files
        "--hash-files",
        type=str,
        nargs="+",
        help=(
            "Pre-computed hash files that can be used in place of calculating hash data prior to"
            " exchange"
        ),
    )
    # Todo: add option to merge to root folder, rather than creating 'exchange' subfolder
    # Todo: for files to be exchanged that share a hash, have an option to only copy one instance
    # Todo: experiment with symlinks to see if they can replace ".references.txt" files

    hash_parser = subparsers.add_parser("hash")
    hash_parser.add_argument(
        "source_paths", type=str, nargs="+", help="File or folder path(s) containing files to hash"
    )
    hash_parser.add_argument(
        "-o",
        "--output",
        type=str,
        help=(
            "File path to output unified hash file to (if not specified, per-source output files"
            " will be generated in the logs folder)"
        ),
    )
    hash_parser.add_argument(
        "-a",
        "--archives",
        action="store_true",
        help="Attempt to hash files within .zip and .7z archive files",
    )
    hash_parser.add_argument(
        "--only-archive-contents",
        action="store_true",
        help=(
            "Attempt to hash files within .zip and .7z archive files, but do not hash the archive"
            " file itself"
        ),
    )
    hash_parser.add_argument(
        "-c",
        "--cache",
        default="vericopy_cache",
        help=(
            "Folder to extract 7z or encrypted zip files to, if the archives flag is used (default"
            " is 'vericopy_cache' folder created in same directory as script)"
        ),
    )
    hash_parser.add_argument(
        "-p",
        "--password",
        type=str,
        help=(
            "Password to attempt for encrypted .zip / .7z files - note that unencrypted archives"
            " will not be blocked from extraction by setting this password"
        ),
    )
    # Todo: add option to 'hash' based on size alone, i.e. quick but unreliable integrity check
    # Todo: add option to recursively extract archives, i.e. archives within archives get processed

    compare_parser = subparsers.add_parser("compare")
    compare_parser.add_argument(
        "source_output_path", type=str, help="Metadata file for source folder"
    )
    compare_parser.add_argument(
        "destination_output_path", type=str, help="Metadata file for destination folder"
    )
    compare_parser.add_argument(
        "-c",
        "--compare-filepaths",
        action="store_true",
        help=(
            "In addition to checking that all hashes in source are in destination, also check that"
            " all source paths are present in destination"
        ),
    )
    compare_parser.add_argument(
        "-m",
        "--missing-files-output",
        type=str,
        help="Path to write filenames of missing files from source to",
    )
    compare_parser.add_argument(
        "--copy-missing-dest",
        type=str,
        help=(
            "Path to copy missing files to - files must still be present at original source"
            " location for this to be successful"
        ),
    )
    # Todo: add 'reconstruct' mode, for turning a merged/exchanged 'view' on a destination drive
    # back into the original source drive folder layout
    # Todo: add 'hashfilemerge' mode, to allow merging of separate hash files based on most recent
    # datetimes

    args = parser.parse_args()

    # Set up logging
    pathlib.Path(args.logfolder).mkdir(parents=True, exist_ok=True)
    log, counter_handler = _prepare_logging(
        datetime_string=datetime_string,
        write_logs=args.log,
        folder_path=args.logfolder,
        identifier="vericopy",
        args=dict(vars(args)),
        show_debug=args.debug,
        write_debug=args.debug,
    )
    if args.command != "compare" or (args.log or args.debug):
        if args.command == "compare":
            what_will_be_generated = "Logs"
        else:
            if args.log or args.debug:
                what_will_be_generated = "Hashes and logs"
            else:
                what_will_be_generated = "Hashes"
        log.info(
            "%s generated will be stored in folder '%s'%s",
            what_will_be_generated,
            args.logfolder,
            (
                "; hashes will be consolidated for all sources in file '{}'".format(args.output)
                if args.command == "hash" and args.output is not None
                else ""
            ),
        )

    if args.command == "copy" or args.command == "move":
        copy_or_move_mode(
            True if args.command == "copy" else False,
            source_paths=sorted(args.source_paths),
            destination_path=args.destination_path,
            run_time_str=datetime_string,
            log_folder_path=args.logfolder,
            only_hash_copied_files=args.only_hash_transferred_files,
            hash_file_paths=args.hash_files,
            hash_algorithms=args.algorithms,
            ignore_dotfiles=args.ignore_dotfiles,
            ignore_windows_volume_folders=args.ignore_windows_volume_folders,
        )
    if args.command == "merge":
        merge_mode(
            source_paths=sorted(args.source_paths),
            destination_path=args.destination_path,
            run_time_str=datetime_string,
            log_folder_path=args.logfolder,
            only_hash_copied_files=args.only_hash_transferred_files,
            hash_file_paths=args.hash_files,
            hash_algorithms=args.algorithms,
            ignore_dotfiles=args.ignore_dotfiles,
            ignore_windows_volume_folders=args.ignore_windows_volume_folders,
        )
    if args.command == "exchange":
        exchange_mode(
            source_paths=sorted(args.source_paths),
            run_time_str=datetime_string,
            log_folder_path=args.logfolder,
            only_hash_copied_files=args.only_hash_transferred_files,
            hash_file_paths=args.hash_files,
            hash_algorithms=args.algorithms,
            ignore_dotfiles=args.ignore_dotfiles,
            ignore_windows_volume_folders=args.ignore_windows_volume_folders,
        )
    if args.command == "hash":
        hash_mode(
            source_paths=sorted(args.source_paths),
            output_path=args.output,
            run_time_str=datetime_string,
            log_folder_path=args.logfolder,
            archives_flag=args.archives,
            only_archive_contents_flag=args.only_archive_contents,
            cache_path=args.cache,
            zip_password=args.password,
            hash_algorithms=args.algorithms,
            ignore_dotfiles=args.ignore_dotfiles,
            ignore_windows_volume_folders=args.ignore_windows_volume_folders,
        )
    if args.command == "compare":
        compare_mode(
            source_file_path=args.source_output_path,
            dest_file_path=args.destination_output_path,
            missing_files_output_path=args.missing_files_output,
            copy_missing_files_path=args.copy_missing_dest,
            compare_filepaths=args.compare_filepaths,
        )

    # Mention any errors and close out
    if counter_handler.count["WARNING"] > 0 or counter_handler.count["ERROR"] > 0:
        log.warning(
            "Script complete; %s warnings/errors occurred requiring review (see log entries"
            " above, replicated in folder '%s'",
            counter_handler.count["WARNING"] + counter_handler.count["ERROR"],
            args.logfolder,
        )
    else:
        log.info("Script complete; no errors reported")


if __name__ == "__main__":
    # Entry point when running script directly
    main()
