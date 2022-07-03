# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Author: Carl Svensson

cmake_minimum_required(VERSION 3.10)

set(GLSL_LANG_VALIDATOR "D:/Tools/shaderc/bin/glslangValidator.exe")

project(Whitecube)

include_directories(include)
include_directories(D:/Tools/Libraries/glfw-3.3.7/include)
link_directories(D:/Tools/Libraries/glfw-3.3.7/lib-vc2022)

add_custom_command(
  OUTPUT "${CMAKE_CURRENT_SOURCE_DIR}/shaders/shader_vert.h"
  COMMAND  "${GLSL_LANG_VALIDATOR}" -G "${CMAKE_CURRENT_SOURCE_DIR}/shaders/shader.vert" -o "${CMAKE_CURRENT_SOURCE_DIR}/shaders/shader_vert.h" --vn "shader_vert"
  DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/shaders/shader.vert"
  COMMENT "Compile vertex shader to SPIR-V header file"
)

add_custom_command(
  OUTPUT "${CMAKE_CURRENT_SOURCE_DIR}/shaders/shader_frag.h"
  COMMAND  "${GLSL_LANG_VALIDATOR}" -G "${CMAKE_CURRENT_SOURCE_DIR}/shaders/shader.frag" -o "${CMAKE_CURRENT_SOURCE_DIR}/shaders/shader_frag.h" --vn "shader_frag"
  DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/shaders/shader.frag"
  COMMENT "Compile fragment shader to SPIR-V header file"
)

add_custom_command(
  OUTPUT "${CMAKE_CURRENT_SOURCE_DIR}/shaders/vert.spv"
  COMMAND  "${GLSL_LANG_VALIDATOR}" -G "${CMAKE_CURRENT_SOURCE_DIR}/shaders/shader.vert" -o "${CMAKE_CURRENT_SOURCE_DIR}/shaders/vert.spv"
  DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/shaders/shader.vert"
  COMMENT "Compile vertex shader to SPIR-V binary file"
)

add_custom_command(
  OUTPUT "${CMAKE_CURRENT_SOURCE_DIR}/shaders/frag.spv"
  COMMAND  "${GLSL_LANG_VALIDATOR}" -G "${CMAKE_CURRENT_SOURCE_DIR}/shaders/shader.frag" -o "${CMAKE_CURRENT_SOURCE_DIR}/shaders/frag.spv"
  DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/shaders/shader.frag"
  COMMENT "Compile fragment shader to SPIR-V binary file"
)

add_custom_target(
  CompileShaders ALL
  DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/shaders/shader_vert.h" "${CMAKE_CURRENT_SOURCE_DIR}/shaders/shader_frag.h"
)

add_custom_target(
  CompileShadersBinary ALL
  DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/shaders/vert.spv" "${CMAKE_CURRENT_SOURCE_DIR}/shaders/frag.spv"
)

add_executable(Whitecube whitecube.cpp src/glad.c)
add_dependencies(Whitecube CompileShaders CompileShadersBinary)

target_link_libraries(Whitecube PUBLIC glfw3)
