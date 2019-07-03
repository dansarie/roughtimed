# CMakeLists.txt
#
# Copyright (C) 2019 Marcus Dansarie <marcus@dansarie.se>

cmake_minimum_required (VERSION 3.10)

project(ROUGHTIMED VERSION 1.0 LANGUAGES C)

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

add_executable(roughtimed config.c roughtimed.c roughtime-common.c)
add_executable(roughtime-keytool roughtime-keytool.c roughtime-common.c)
add_executable(roughtime-test test-roughtime.c roughtime-common.c)
add_executable(testtimex testtimex.c)
target_link_libraries(roughtimed ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(roughtimed OpenSSL::SSL m)
target_link_libraries(roughtime-keytool OpenSSL::SSL)
target_link_libraries(roughtime-test OpenSSL::SSL)
add_definitions(-DVERSION="${ROUGHTIMED_VERSION}")

set(CMAKE_C_FLAGS "-march=native -Ofast -g -Wall -Wpedantic")

install(TARGETS roughtimed roughtime-keytool DESTINATION bin)
