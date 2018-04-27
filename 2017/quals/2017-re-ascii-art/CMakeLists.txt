project(rick_client CXX)
cmake_minimum_required(VERSION 2.6.2)

set(CMAKE_CXX_FLAGS "-std=c++0x -fno-rtti -g0 -O -s -Wall -fno-exceptions")
set(GTEST_ROOT /usr/src/gtest/)
include_directories(. /usr/src/gtest)

#execute_process(COMMAND protoc 
#        -I ${CMAKE_SOURCE_DIR}/src/proto
#        --cpp_out=${CMAKE_SOURCE_DIR}/src/proto/
#        ${CMAKE_SOURCE_DIR}/src/proto/aart_message.proto)

add_executable(aart_client
  src/client/http_client.h
  src/client/http_client.cc
  src/client/string_encoding.cc
  src/client/aart_client.cc
  src/proto/aart_message.pb.cc
)

add_executable(unittests
  ${GTEST_ROOT}/src/gtest-all.cc
  src/client/string_encoding_unittest.cc
  src/client/string_encoding.h
  src/client/string_encoding.cc
  src/client/http_client.h
  src/client/http_client.cc
  src/client/unittests.cc
)

SET_TARGET_PROPERTIES (aart_client PROPERTIES LINK_SEARCH_START_STATIC 1)
SET_TARGET_PROPERTIES (aart_client PROPERTIES LINK_SEARCH_END_STATIC 1)

target_link_libraries(unittests ${GTEST_LIBRARIES} ${GTEST_MAIN_LIBRARIES} pthread)
target_link_libraries(aart_client /usr/lib/x86_64-linux-gnu/libprotobuf.a)
set(CMAKE_EXE_LINKER_FLAGS "-static-libgcc -static-libstdc++")

