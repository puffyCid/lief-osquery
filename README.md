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
Download the prebuilt nightly LIEF binaries from https://lief.quarkslab.com/packages/sdk/
Place the include and lib folders into the checkedout directory

Place the cloned directory into the external directory in the checkedout osquery directory
Follow the osquery build process at https://osquery.readthedocs.io/en/stable/development/building/
When configuring the build osquery include the argument `-DLIEF_ROOT=<path to checkedout lief-osquery/{extension\_pe or extension\_macho}>`  
```
cmake -DCMAKE_OSX_DEPLOYMENT_TARGET=10.11 -DLIEF_ROOT=<path to lief-osquery/darwin>  ..
cmake -G "Visual Studio 16 2019" -A x64 -DLIEF_ROOT=<path to lief-osquery/windows>..
```
Extension binareis are also avaiable to download
