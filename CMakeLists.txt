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

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

add_executable(roughtimed
               src/config.c
               src/roughtimed.c
               src/roughtime-common.c)
add_executable(roughtime-keytool
               src/roughtime-keytool.c
               src/roughtime-common.c)
add_executable(roughtime-test
               src/test-roughtime.c
               src/roughtime-common.c)
add_executable(testtimex
               src/testtimex.c)
target_link_libraries(roughtimed ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(roughtimed OpenSSL::SSL m)
target_link_libraries(roughtime-keytool OpenSSL::SSL)
target_link_libraries(roughtime-test OpenSSL::SSL)
add_definitions(-DVERSION="${ROUGHTIMED_VERSION}")

set(CMAKE_C_FLAGS "-march=native -Ofast -g -Wall -Wpedantic -Wextra -Werror")

install(TARGETS roughtimed roughtime-keytool DESTINATION bin)
