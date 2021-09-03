# CMakeLists.txt
#
# Copyright (C) 2019-2021 Marcus Dansarie <marcus@dansarie.se>
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

project(ROUGHTIMED VERSION 1.1.0 LANGUAGES C)

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
