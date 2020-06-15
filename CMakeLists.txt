cmake_minimum_required(VERSION 3.4)
project(evltls)

# export compile_commands.json
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_FLAGS "-g ${CMAKE_CXX_FLAGS}")
set(CMAKE_C_FLAGS   "-g ${CMAKE_C_FLAGS}")

set(LIB_EVLTLS evltls)

set(kproxy_lib kpx)
set(LIB_EVLTLS_SRC 
    src/evltls.cpp
    )

include_directories("${CMAKE_CURRENT_LIST_DIR}/include")

# openssl #{
if (WIN32)
    set(OPENSSL_PATH ./third_party/openssl)
    find_file(OPENSSL_INCLUDE_SSL_H NAME ssl.h PATH_SUFFIXES include/openssl HINTS ${OPENSSL_PATH})
    find_library(OPENSSL_CRYPTO_LIBRARY NAME libeay32 PATH_SUFFIXES lib HINTS ${OPENSSL_PATH})
    find_library(OPENSSL_SSL_LIBRARY    NAME ssleay32 PATH_SUFFIXES lib HINTS ${OPENSSL_PATH})
    get_filename_component(OPENSSL_INCLUDE_DIR_ ${OPENSSL_INCLUDE_SSL_H} DIRECTORY)
    get_filename_component(OPENSSL_INCLUDE_DIR  ${OPENSSL_INCLUDE_DIR_}  DIRECTORY)
else()
    find_package(OpenSSL)
endif()
include_directories(${OPENSSL_INCLUDE_DIR})
#}

# evltls library #{
add_library(${LIB_EVLTLS} STATIC ${LIB_EVLTLS_SRC})

target_link_libraries(${LIB_EVLTLS} ${OPENSSL_CRYPTO_LIBRARY})
target_link_libraries(${LIB_EVLTLS} ${OPENSSL_SSL_LIBRARY})
#}

