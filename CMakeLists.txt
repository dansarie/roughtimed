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
set(CMAKE_C_FLAGS "-march=native -Ofast -g -Wall -Wpedantic -Wextra -Werror")

add_definitions(-DVERSION="${ROUGHTIMED_VERSION}")

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(CHECK REQUIRED check)

add_executable(roughtimed
               src/config.c
               src/roughtimed.c
               src/roughtime_common.c)
target_link_libraries(roughtimed ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(roughtimed OpenSSL::SSL m)

add_executable(roughtime-keytool
               src/roughtime-keytool.c
               src/roughtime_common.c)
target_link_libraries(roughtime-keytool OpenSSL::SSL)

add_executable(roughtime-stress-tester
               src/roughtime-stress-tester.c
               src/roughtime_common.c)
target_link_libraries(roughtime-stress-tester OpenSSL::SSL)

add_executable(testtimex
               src/testtimex.c)

add_executable(test_roughtime
               src/config.c
               src/roughtime_common.c
               tests/test_config.c
               tests/test_roughtime.c)
target_link_libraries(test_roughtime ${CHECK_LIBRARIES})
target_link_libraries(test_roughtime OpenSSL::SSL)
target_compile_options(test_roughtime PRIVATE --coverage)
target_link_options(test_roughtime PRIVATE --coverage)
add_custom_target(test
                 COMMAND test_roughtime
                 COMMAND mkdir -p coverage
                 COMMAND gcovr --root ${CMAKE_SOURCE_DIR}
                 DEPENDS test_roughtime
                 WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

install(TARGETS roughtimed roughtime-keytool DESTINATION bin)
