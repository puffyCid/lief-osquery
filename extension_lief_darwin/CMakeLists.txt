project(LiefExt VERSION 1.0
  DESCRIPTION "LIEF Extension for Osquery"
  LANGUAGES CXX)

include(${CMAKE_SOURCE_DIR}/external/cmake/cmakelibs.cmake)

set(LIEF_DIR CACHE PATH ${CMAKE_INSTALL_PREFIX})
list(APPEND CMAKE_MODULE_PATH ${LIEF_DIR}/share/LIEF/cmake)
include(FindLIEF)
find_package(LIEF REQUIRED COMPONENTS STATIC)

function(osqueryExtensionsExampleMain)
  addOsqueryExtension(lief_macho src/main.cpp src/macholibraries.cpp src/machofunctions.cpp src/machosections.cpp)
  target_include_directories(lief_macho PUBLIC PUBLIC ${LIEF_INCLUDE_DIRS})

set_property(TARGET lief_macho PROPERTY CXX_STANDARD           11)
set_property(TARGET lief_macho PROPERTY CXX_STANDARD_REQUIRED  ON)
target_link_libraries(lief_macho PUBLIC ${LIEF_LIBRARIES})

    target_link_libraries(lief_macho PRIVATE
        osquery_sdk_pluginsdk
        osquery_extensions_implthrift
    )
endfunction()

osqueryExtensionsExampleMain()
