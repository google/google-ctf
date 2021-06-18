# Copyright 2020 Google LLC
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
import functools as f
a,b,c,d=input('> '),input('> '),input('> '),input('> ')
if int(a)==int(b)-1==int(c)-2==int(d)+-3:
    n=int(''.join(map(str,(a,b,c,d))))
    if f.reduce(lambda x,y:x*(int(''.join(map(str,(a,b,c,d))))%y),range(1,int(int(''.join(map(str,(a,b,c,d))))**.5)+1)):
        print('HCL8{The_m4gic_number_is_%d}'%(a**b*c**d))
