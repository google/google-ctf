# Copyright (C) 2022 Google LLC
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
cmake_minimum_required (VERSION 3.0)
project ("keygen" C CXX ASM)
set(CMAKE_CXX_STANDARD 11)

# Set default build type.
if(NOT CMAKE_BUILD_TYPE)
  message(STATUS "Setting build type to 'Release' as none was specified.")
  set(CMAKE_BUILD_TYPE "Release" CACHE STRING
      "Choose the type of build, options are: Debug Release RelWithDebInfo MinSizeRel."
      FORCE)
endif()

set(PQCLEAN_DIR ${CMAKE_SOURCE_DIR}/third_party/PQClean)
set(PQCLEAN_COMMON_DIR ${PQCLEAN_DIR}/common)
set(KYBER_DIR ${PQCLEAN_DIR}/crypto_kem/kyber512-90s/clean)
add_library(kyber_lib
  ${KYBER_DIR}/cbd.c
  ${KYBER_DIR}/indcpa.c
  ${KYBER_DIR}/kem.c
  ${KYBER_DIR}/ntt.c
  ${KYBER_DIR}/poly.c
  ${KYBER_DIR}/polyvec.c
  ${KYBER_DIR}/reduce.c
  ${KYBER_DIR}/symmetric-aes.c
  ${KYBER_DIR}/verify.c
  ${PQCLEAN_COMMON_DIR}/aes.c
  ${PQCLEAN_COMMON_DIR}/sha2.c
  ${PQCLEAN_COMMON_DIR}/randombytes.c
)
target_include_directories(kyber_lib
  PUBLIC
  ${PQCLEAN_COMMON_DIR}
  ${KYBER_DIR}
)

add_executable(keygen
  main.cc
)
target_link_libraries(keygen
  kyber_lib
)

