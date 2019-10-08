cmake_minimum_required(VERSION 3.0.2 FATAL_ERROR)

if (NOT OPENSSL_FOUND)
  find_package(OpenSSL REQUIRED)
endif()

set(SSSLIB "/home/ilya/Code/Cpp/sss")
set(LIBCPPCODEC "/home/ilya/Code/Cpp/cppcodec")

include_directories(${SSSLIB} ${LIBCPPCODEC})

add_library(libsss SHARED IMPORTED)
set_target_properties(libsss PROPERTIES IMPORTED_LOCATION "${SSSLIB}/libsss.a")

add_library(libcppcodec ${LIBCPPCODEC})
set_target_properties(libcppcodec PROPERTIES LINKER_LANGUAGE CXX)

add_executable(generate-random-id generate-random-id.cpp )
target_link_libraries(generate-random-id libsss tl_api ton_crypto keys)

target_include_directories(generate-random-id PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>/..)

add_executable(json2tlo json2tlo.cpp )
target_link_libraries(json2tlo tl_api ton_crypto keys)
target_include_directories(json2tlo PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>/..)
