# Vericopy

This Python script provides various usage modes for secure local file copying and hashing. Hash data is captured and logged for paths before and after copying, to confirm that transfers were successful and enable optional copying modes such as `merge` and `exchange`, in which files will only be transferred from sources that are not already present somewhere in the destination. Multiprocessing is used for hashing to optimise performance.

## Prerequisites

Python 3.7 or later is required, with the `tqdm` progress bar module installed (`pip install tqdm`).

This script has been tested using Python versions 3.7, 3.8.5, and 3.95, running on macOS 11.4, Ubuntu 20.04, and Windows 10 20H2.

## Script usage

The script has six usage modes, outlined below. Hash data generated will be written to a log folder, by default created in folder `vericopy_logs`.

Multiprocessing will be used to hash data on each of the source and destination paths simultaneously. Performance will be maximised if the provided paths are on separate drives.

Script-wide flags can be viewed using: `python3 vericopy.py --help`, and are as follows:

- `-l` or `--log`: opt to write the status messages displayed in the console to a log file in the log folder.
- `-d` or `--debug`: display debug messages and write these to a dedicated debug log file in the log folder.
- `--logfolder [str]`: folder to write logs to (if not specified, the default of `vericopy_logs` will be used).
- `--algorithms [md5, sha1, sha256]`: SHA1 is the hashing algorithm used by default; this flag allows for other algorithm(s) to be specified, from options 'md5', 'sha1' and 'sha256'.
- `--ignore-dotfiles`: files and folders beginning with `.` will not be processed (such folders are typically hidden and contain system/settings data).
- `--ignore-windows-volume-folders`: folders named `System Volume Information` and `$RECYCLE.BIN` will not be processed (such folders typically contain hidden Windows system information).

Usage example incorporating flags:

    python3 vericopy.py --algorithms md5 sha1 sha256 -l --logfolder alternate_log_folder --ignore-dotfiles --ignore-windows-volume-folders [mode and mode arguments]

## Usage modes

### Copy

Files in one or more source paths will be copied to a destination folder, with hash verification performed before and after the copy to verify transfer completed successfully. Files within subfolders will be included for this and other modes (i.e. recursive copy). Absolute or relative paths may be provided; all metadata generated will revert to absolute paths.

Syntax:

    python3 vericopy.py copy source_path [source_path ...] destination_path [flags]

Usage example:

    python3 vericopy.py copy gov.archives.arc.1155023 TourTheInternationalSpaceStation space_videos

The above will `copy` all files in folders `gov.archives.arc.1155023` and `TourTheInternationalSpaceStation` to folder `space_videos`, with file hashing performed before and after the copy to confirm success.

The available flags can be viewed using: `python3 vericopy.py copy --help`, and are as follows:

- `--only-hash-transferred-files`: instead of performing a full before-and-after hash of the destination folder, only those files transferred will be hashed and verified. Useful if there are already files present in the destination folder and these files do not need capturing within the metadata generated.
- `--hash-files [str ... str]`: one or more (space separated) paths to pre-computed hash files, to avoid re-generation of hash data for the source(s) and destination. These hash files may be generated using the `hash` mode, or will be present in the log folder from any previous executions of `copy`, `move`, or `merge`.

### Move

The usage and available flags for `move` are identical to `copy`, except files will be moved (i.e. deleted from the source after the transfer is verified) instead of copied. The 'move' is achieved by initially copying files from source(s) to destination, then running a hash check that the transfer was successful - following confirmation, the files will be deleted from the source(s).

### Merge

Hash data will be generated and compared between source(s) and destination, and only those files that are not present somewhere within the destination path will be copied. When using this mode, data will be transferred to a `[timestamp]_merge` subfolder in the destination. This subfolder contains:

- A folder for each of the source(s), within which are the unique files that were not previously present in the destination.
- A folder `merge_hash_references`, which contains `[source_file_filename].references.txt` files for each of the files on the source(s) that were already present on the destination before the transfer. Each of these files contain a file list of where copies of the original source file may be found on the destination (as this is a hash-based reference, the filenames on the destination may be different than that of the source).

This means that a file is created on the destination for every file in the source(s), but for those files that already existed somewhere within the destination, this file will be a small `.references.txt` file rather than the original data. Inclusion of these reference files allows for a 'view' of the original source(s) that may be reconstructed later if desired (provided that no data is deleted on the destination in the meantime).

Syntax:

    python3 vericopy.py merge source_path [source_path ...] destination_path [flags]

Usage example:

    python3 vericopy.py merge gov.archives.arc.1155023 TourTheInternationalSpaceStation space_videos

The above will `merge` all files in folders `gov.archives.arc.1155023` and `TourTheInternationalSpaceStation` into `space_videos` - the files in `gov.archives.arc.1155023` and `TourTheInternationalSpaceStation` that were not present in `space_videos` will be fully copied, while `.references.txt` files will be created in reference to files that were already present. This data will be placed in a `[timestamp]_merge` subfolder in `space_videos`.

The available flags are the same as for the `copy` mode listed above.

### Exchange

Similarly to `merge`, hash data will be generated and compared between two or more source(s). Each source will then receive a copy of any files stored within the other source(s) that were not previously present somewhere within the source folder. When using this mode, data will be transferred to a `[timestamp]_exchange` subfolder in each source, with contents and structure as per the equivalent in the `merge` mode above.

Syntax:

    python3 vericopy.py exchange source_path source_path [source_path ...] [flags]

Usage example:

    python3 vericopy.py exchange gov.archives.arc.1155023 TourTheInternationalSpaceStation space_videos

The above will `exchange` all files in folders `gov.archives.arc.1155023`, `TourTheInternationalSpaceStation`, and `space_videos` - each folder will receive copies of files that were previously only present within the other two folders. This data will be placed in a `[timestamp]_exchange` subfolder in each folder.

The available flags are the same as for the `copy` mode listed above.

### Hash

Hash data will be generated for the provided source(s) with no subsequent file transfers. Useful to pre-compute hash data for one of the modes above. This mode also allows for hashing of files within `.zip` and `.7z` archives if specified using the flags detailed below.

Syntax:

    python3 vericopy.py hash source_path [source_path ...] [flags]

Usage example:

    python3 vericopy.py hash gov.archives.arc.1155023 TourTheInternationalSpaceStation

The above will `hash` all files in folders `gov.archives.arc.1155023` and `TourTheInternationalSpaceStation`, with results placed in the log folder.

The available flags can be viewed using: `python3 vericopy.py hash --help`, and are as follows:

- `-o [str]` or `--output [str]`: a file path to output unified hash metadata to, taken from all of the source(s). If not specified, per-source hash metadata will still be available in the log folder.
- `-a` or `--archives`: attempt to hash files within archive files. At this time only `.zip` and `.7z` files are supported, and encrypted `.zip` files and all `.7z` files require the `7z` commandline tool to be installed and accessible on the system PATH.
- `--only-archive-contents`: attempt to hash files within archive files, but do not hash the archive file itself. E.g. the files contained within `sample.zip` would be hashed, but `sample.zip` itself would not be hashed.
- `-c [str]` or `--cache [str]`: if attempting to hash files within archive files, any encrypted `.zip` files or `.7z` files will need to be temporarily extracted in order to hash the files within. The default cache folder location will be `vericopy_cache` within the script folder, however a custom cache folder may be specified with this flag. As this folder will be deleted at the end of script execution, for safety, it must not exist before the script is run.
- `-p [str]` or `--password [str]`: if attempting to hash files within encrypted archive files, specify the password to attempt with this flag. Unencrypted archive files will still extract even if the password is set. Note that terminal history on your system may reveal this password to other users.

### Compare

Hash files generated while transferring data or using the `hash` mode may be compared with the `compare` mode, to determine if all hash values in a 'source' hash file can be found within a 'destination' hash file.

Syntax:

    python3 vericopy.py compare source_output_path destination_output_path [flags]

Usage example:

    python3 vericopy.py compare hashes-original.txt hashes-updated.txt

The above will `compare` the hashes within `hashes-original.txt` and `hashes-updated.txt`, checking that all hashes in `hashes-original.txt` are present at least once in `hashes-updated.txt`.

The available flags can be viewed using: `python3 vericopy.py compare --help`, and are as follows:

- `-c` or `--compare-filepaths`: by default, only hash values will be compared, rather than file paths as well as hash values. This behaviour allows for files to be moved between sources, and for duplicates of files to be deleted. Using this flag will also compare that all file paths in the source file can be found in the destination file.
- `-m [str]` or `--missing-files-output [str]`: any missing hashes will be reported in command line output; these may be consolidated to a missing file list in an output file path using this flag.
- `--copy-missing-dest [str]`: any hash values found to be missing will have a copy of the source file copied to a folder specified using this flag. Note that the files must still be present at the original source locations for this to work.

## Privacy, log data, and uninstallation

This script runs entirely locally; no third party services are communicated with.

Log data and hash metadata is stored by default in folder `vericopy_logs` (created in the folder that the script is executed in). Debug logs capture system details (including Python version and operating system), command line arguments used, and events occurring during script execution. Archive passwords are not recorded in these logs, but will be retained on the local system in terminal history.

Full uninstallation can be achieved by:

1. Deleting the script and any other downloaded files (e.g. the readme and license).
2. Deleting the logs folder (`vericopy_logs` by default).
3. If desired, removing records of archive passwords stored in terminal history.
4. If desired, removing the `tqdm` library and Python runtime.

## Known issues

1. A [Python bug](https://bugs.python.org/issue38428) may cause issues in Windows when trying to quit the script using `CTRL+C`. A `SIGBREAK` can be sent instead using `CTRL+BREAK`, or by invoking the on-screen keyboard (`WIN+R`, then run `osk.exe`) and using its `Ctrl+ScrLk` keys.

## Contributing

If you would like to contribute, please fork the repository and use a feature branch. Pull requests are warmly welcome.

## Licensing

The code in this project is licensed under the MIT License.
