cmake_minimum_required(VERSION 3.4)
project(evltls)

# export compile_commands.json
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_FLAGS "-g ${CMAKE_CXX_FLAGS}")
set(CMAKE_C_FLAGS   "-g ${CMAKE_C_FLAGS}")

set(LIB_EVLTLS evtls)

set(kproxy_lib kpx)
set(LIB_EVLTLS_SRC 
    lib/utils.cpp
    lib/events.cpp
    lib/logger.cpp
    lib/stream.cpp
    lib/stream_tls.cpp
    lib/shared_memory.cpp
    lib/stream_object.cpp
    lib/object_manager.cpp
    lib/help_class.cpp
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

target_include_directories(${LIB_EVLTLS}
    PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    PRIVATE
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/lib>)

target_link_libraries(${LIB_EVLTLS} ${OPENSSL_CRYPTO_LIBRARY})
target_link_libraries(${LIB_EVLTLS} ${OPENSSL_SSL_LIBRARY})
#}

# test #{
file(GLOB TEST_FILES_CPP "${CMAKE_CURRENT_LIST_DIR}/tests/test-*.cpp")
file(GLOB TEST_FILES_CX  "${CMAKE_CURRENT_LIST_DIR}/tests/test-*.cx")
file(GLOB TEST_FILES     "${CMAKE_CURRENT_LIST_DIR}/tests/test-*.c")
list(APPEND TEST_FILES ${TEST_FILES_CPP} ${TEST_FILES_CX})
foreach (test_file IN LISTS TEST_FILES)
    get_filename_component(fname ${test_file} NAME_WE)
    string(LENGTH ${fname} fname_len)
    math(EXPR name_len "${fname_len} - 5")
    string(SUBSTRING ${fname} 5 ${name_len} execname)
    message(STATUS "test=${execname}")
    add_executable(${execname} ${test_file})
    add_dependencies(${execname} ${LIB_EVLTLS})
    target_link_libraries(${execname} ${LIB_EVLTLS})
    set_target_properties(${execname} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests")
endforeach()
#}

