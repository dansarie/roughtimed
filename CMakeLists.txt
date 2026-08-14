# CMakeLists.txt
#
# Copyright (C) 2019-2026 Marcus Dansarie <marcus@dansarie.se>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.


cmake_minimum_required (VERSION 3.10)

project(ROUGHTIMED VERSION 1.3.0 LANGUAGES C)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_FLAGS "-march=native -O3 -g -Wall -Wpedantic -Wextra -Werror")

add_definitions(-DVERSION="${ROUGHTIMED_VERSION}")

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(CHECK REQUIRED check)

add_executable(roughtimed
               src/config.c
               src/roughtimed.c
               src/roughtime_common.c
               tests/hooks.c)
target_link_libraries(roughtimed ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(roughtimed OpenSSL::SSL m)

add_executable(roughtime-keytool
               src/roughtime-keytool.c
               src/roughtime_common.c
               tests/hooks.c)
target_link_libraries(roughtime-keytool OpenSSL::SSL)

add_executable(roughtime-stress-tester
               src/roughtime-stress-tester.c
               src/roughtime_common.c
               tests/hooks.c)
target_link_libraries(roughtime-stress-tester OpenSSL::SSL)

add_executable(testtimex
               src/testtimex.c)

set(TEST_SOURCES
    src/config.c
    src/roughtime_common.c
    tests/hooks.c
    tests/test_config.c
    tests/test_roughtime.c
    tests/test_roughtime_common.c)

function(add_test_executable name)
    add_executable(${name}
                   src/config.c
                   src/roughtime_common.c
                   tests/hooks.c
                   tests/test_config.c
                   tests/test_roughtime.c
                   tests/test_roughtime_common.c)
    target_link_libraries(${name} ${CHECK_LIBRARIES})
    target_link_libraries(${name} OpenSSL::SSL)
    target_compile_options(${name} PRIVATE -DTESTING)
endfunction()

add_test_executable(test_roughtime)
target_compile_options(test_roughtime PRIVATE -O0 --coverage)
target_link_options(test_roughtime PRIVATE --coverage)

add_test_executable(test_roughtime_asan)
target_compile_options(test_roughtime_asan PRIVATE -O0 -fsanitize=address,undefined -fno-omit-frame-pointer)
target_link_options(test_roughtime_asan PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)

add_custom_target(test
                 COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --cyan "Running tests with coverage analysis"
                 COMMAND test_roughtime
                 COMMAND mkdir -p coverage
                 COMMAND gcovr --root ${CMAKE_SOURCE_DIR}
                 COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --cyan "Running tests with address and undefined behavior sanitizers"
                 COMMAND test_roughtime_asan
                 DEPENDS test_roughtime test_roughtime_asan
                 WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_property(TARGET test APPEND PROPERTY
             ADDITIONAL_CLEAN_FILES "${CMAKE_BINARY_DIR}/coverage")

add_custom_target(infer
                  COMMAND infer run --compilation-database build/compile_commands.json
                  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

install(TARGETS roughtimed roughtime-keytool DESTINATION bin)
