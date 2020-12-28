lief-osquery is a simple extension that provides a way to parse PE and MACHO files using osquery using the [LIEF](https://lief.quarkslab.com/) library.

These extensions provides the follow tables:
* PE extension
  * pe_info - Basic info about a PE file (ex: number of sections, entrypoint, number of imported/exported functions, signed status, PIE status, etc)
  * pe_sections - Info about the PE file sections
  * pe_functions - Info about imported and exported functions
  * pe_libraries - Info about imported DLLs
  * pe_signature - Info the signature data (if the file is signed)
* MACHO extension
  * macho_info - Basic info abouta MACHO file (ex: number of sections, entrypoint, number of imported/exported functions, PIE status, etc)
  * macho_sections - Info about the MACHO file sections
  * macho_functions - Info about imported and exported functions
  * macho_libraries - Info about imported libraries
  
# How to install and run
Download the compiled extension(s) from the GitHub releases link  
Run the extensions with `osqueryi --extension <path to extension>` or include the extension in a osquery flag/config file

# How to build
Clone this repository  
Clone the osquery respository  
Download the prebuilt nightly Windows and/or Darwin LIEF binaries from https://lief.quarkslab.com/packages/sdk/  
Extract LIEF into the extension\_lief\_darwin/ and/or extension\_lief\_windows/

Place the extension\_lief\_darwin and/or extension\_lief\_windows into the `external` directory in osquery  
Follow the osquery build process at https://osquery.readthedocs.io/en/stable/development/building/  
When configuring the build osquery include the argument `-DLIEF_ROOT=<path to checkedout lief-osquery/{extension_lief_windows or extension_lief_darwin}>`  
```
cmake -DCMAKE_OSX_DEPLOYMENT_TARGET=10.11 -DLIEF_ROOT=<path to osquery/external/extension_lief_darwin>  ..
cmake -G "Visual Studio 16 2019" -A x64 -DLIEF_ROOT=<path to osquery\external\extension_lief_windows> -DLIEF_LIBRARY=<path to osquery\external\extension_lief_windows\lib\LIEFMT.lib> ..
```
Extension binareis are also available to download
# Usage
```
./osquery/osqueryi --extension external/extension_lief_darwin/lief_macho.ext
Using a virtual database. Need help, type '.help'
osquery> select * from macho_info where path = '/usr/local/bin/osqueryd';
+-------------------------+----------+--------+------------+-------------------+-------------------+-------------+-------------+--------+--------+--------------+---------------------+------------------------------+------------------------------+--------------------+
| path                    | filename | arch   | entrypoint | build_version_min | build_version_sdk | version_min | version_sdk | is_pie | has_nx | is_encrypted | number_of_libraries | number_of_imported_functions | number_of_exported_functions | number_of_sections |
+-------------------------+----------+--------+------------+-------------------+-------------------+-------------+-------------+--------+--------+--------------+---------------------+------------------------------+------------------------------+--------------------+
| /usr/local/bin/osqueryd | osqueryd | x86_64 | 10012dd45  |                   |                   | 10.11.0     | 10.14.0     | 1      | 1      | 0            | 21                  | 1077                         | 372                          | 24                 |
+-------------------------+----------+--------+------------+-------------------+-------------------+-------------+-------------+--------+--------+--------------+---------------------+------------------------------+------------------------------+--------------------+

```
