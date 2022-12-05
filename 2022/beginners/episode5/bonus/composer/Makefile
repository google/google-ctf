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
RESIZE='1119x628!'

all:
	convert -depth 8 background.png background.rgb
	convert -depth 8 ../third_party/epto-fonts/display-8x16-modified.png display-8x16.rgb
	clang++ -Wall -Wextra -fsanitize=address \
	  -O3 -ggdb \
	  -std=c++17 \
	  -Wno-unused-const-variable \
	  -Wno-unused-variable \
	  -o composer \
	  -I ../third_party/NetSock \
	  main.cc \
	  ../third_party/NetSock/NetSock.cpp

images:
	convert -depth 8 glass.png glass.rgba
	convert -depth 8 ../clips/selected_frames/lamp_on.png -resize ${RESIZE} lamp_on.rgb
	convert -depth 8 ../clips/selected_frames/lamp_off.png -resize ${RESIZE} lamp_off.rgb
	convert -depth 8 ../clips/selected_frames/lamp_turning_on_0.png -resize ${RESIZE} lamp_turning_on_0.rgb
	convert -depth 8 ../clips/selected_frames/lamp_turning_on_1.png -resize ${RESIZE} lamp_turning_on_1.rgb
	convert -depth 8 ../clips/selected_frames/lamp_turning_on_2.png -resize ${RESIZE} lamp_turning_on_2.rgb
	convert -depth 8 ../clips/selected_frames/lamp_turning_on_3.png -resize ${RESIZE} lamp_turning_on_3.rgb
	convert -depth 8 ../clips/selected_frames/lamp_turning_off_0.png -resize ${RESIZE} lamp_turning_off_0.rgb
	convert -depth 8 ../clips/selected_frames/lamp_turning_off_1.png -resize ${RESIZE} lamp_turning_off_1.rgb
	convert -depth 8 ../clips/selected_frames/lamp_turning_off_2.png -resize ${RESIZE} lamp_turning_off_2.rgb
	convert -depth 8 ../clips/selected_frames/lamp_turning_off_3.png -resize ${RESIZE} lamp_turning_off_3.rgb

test: all
	./composer
