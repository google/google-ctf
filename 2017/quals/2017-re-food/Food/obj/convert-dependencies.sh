#!/bin/bash -eu
#
# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.



#!/bin/sh
# AUTO-GENERATED FILE, DO NOT EDIT!
if [ -f $1.org ]; then
  sed -e 's!^Q:/Dev/cygwin64/lib!/usr/lib!ig;s! Q:/Dev/cygwin64/lib! /usr/lib!ig;s!^Q:/Dev/cygwin64/bin!/usr/bin!ig;s! Q:/Dev/cygwin64/bin! /usr/bin!ig;s!^Q:/Dev/cygwin64/!/!ig;s! Q:/Dev/cygwin64/! /!ig;s!^Q:!/cygdrive/q!ig;s! Q:! /cygdrive/q!ig;s!^D:!/cygdrive/d!ig;s! D:! /cygdrive/d!ig;s!^C:!/cygdrive/c!ig;s! C:! /cygdrive/c!ig;' $1.org > $1 && rm -f $1.org
fi
