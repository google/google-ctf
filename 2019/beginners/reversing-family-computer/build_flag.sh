#!/bin/bash

# Copyright 2019 Google LLC
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

# Requires packages: imagemagick

# Use ImageMagick to create a flag with exif data stripped
convert -background blue -fill white -font "Times-New-Roman" -pointsize 128 \
    "label:$2" -strip flag_$1.png

# Check that the file size is greater than 4KiB
filesize=$(stat -c "%s" flag_$1.png)
if (( $filesize <= 4096 ))
then
  >&2 echo "flag.png is less than 4KiB, consider adding more text."
fi
