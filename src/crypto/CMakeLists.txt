cmake_minimum_required(VERSION 3.15)
project(libcrypto VERSION 4.2 LANGUAGES C CXX)
 
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
 
if(NOT MSVC)
    message(FATAL_ERROR "libcrypto requiere arquitectura Win y compilador MSVC.")
endif()
 
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(PLATFORM_DIR "x32")
else()
    set(PLATFORM_DIR "x64")
endif()

set(ARQUITECTURE_DIR ${CMAKE_SYSTEM_PROCESSOR})
if(NOT ARQUITECTURE_DIR)
    set(ARQUITECTURE_DIR ${CMAKE_HOST_SYSTEM_NAME})
endif()

set(DIR_BUILD "${PLATFORM_DIR}-${ARQUITECTURE_DIR}")
 
set(SRC_libcrypto
    "${CMAKE_CURRENT_SOURCE_DIR}/../core.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/../core.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/core/core_crypto.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/core/core_crypto.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/core/crypto.rc"
)
 
add_library(libcrypto SHARED ${SRC_libcrypto})
 
set_target_properties(libcrypto PROPERTIES LINK_FLAGS "/DEF:${CMAKE_CURRENT_SOURCE_DIR}/core/crypto.def")
 
set_target_properties(libcrypto PROPERTIES
    PREFIX ""
    OUTPUT_NAME "libcrypto"
    SUFFIX ".dll"
    WINDOWS_EXPORT_ALL_SYMBOLS FALSE 
) 

target_compile_definitions(libcrypto PRIVATE
    WIN32 _WINDOWS _USRDLL UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS TARGET_OS_WIN32 WIN32_LEAN_AND_MEAN
) 

target_link_libraries(libcrypto PRIVATE crypt32 bcrypt ncrypt ${VFP_LIB})

set(DIR_BIN "${CMAKE_CURRENT_SOURCE_DIR}/../../bin/${DIR_BUILD}")

set_target_properties(libcrypto PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${DIR_BIN}/$<CONFIG>"
    LIBRARY_OUTPUT_DIRECTORY "${DIR_BIN}/$<CONFIG>"
    ARCHIVE_OUTPUT_DIRECTORY "${DIR_BIN}/$<CONFIG>"
)
 
add_custom_command(TARGET libcrypto POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        "${CMAKE_CURRENT_SOURCE_DIR}/examples"
        "$<TARGET_FILE_DIR:libcrypto>/"
)
