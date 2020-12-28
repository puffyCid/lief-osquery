project(LiefExt VERSION 1.0
  DESCRIPTION "LIEF Extension for Osquery"
  LANGUAGES CXX)

include(${CMAKE_SOURCE_DIR}/external/cmake/cmakelibs.cmake)

set(LIEF_ROOT CACHE PATH ${CMAKE_INSTALL_PREFIX})
list(APPEND CMAKE_MODULE_PATH ${LIEF_ROOT}/share/LIEF/cmake)
include(FindLIEF)
find_package(LIEF REQUIRED COMPONENTS STATIC)

function(osqueryExtensionsExampleMain)
  addOsqueryExtension(lief_pe src/main.cpp src/pelibraries.cpp src/pefunctions.cpp src/pesections.cpp src/pesig.cpp)
  if (MSVC)
    # Used for the 'and', 'or' ... keywords - See: http://www.cplusplus.com/reference/ciso646/
    target_compile_options(lief_pe PUBLIC /FIiso646.h)
	set_property(TARGET lief_pe PROPERTY LINK_FLAGS /NODEFAULTLIB:MSVCRT)
  endif()
  target_include_directories(lief_pe PUBLIC PUBLIC ${LIEF_INCLUDE_DIRS})

set_property(TARGET lief_pe PROPERTY CXX_STANDARD           11)
set_property(TARGET lief_pe PROPERTY CXX_STANDARD_REQUIRED  ON)
target_link_libraries(lief_pe PUBLIC ${LIEF_LIBRARIES})

    target_link_libraries(lief_pe PRIVATE
        osquery_sdk_pluginsdk
        osquery_extensions_implthrift
    )
endfunction()

osqueryExtensionsExampleMain()
