REM Copyright 2018 Google Inc.
REM
REM Licensed under the Apache License, Version 2.0 (the "License");
REM you may not use this file except in compliance with the License.
REM You may obtain a copy of the License at
REM
REM      http://www.apache.org/licenses/LICENSE-2.0
REM
REM Unless required by applicable law or agreed to in writing, software
REM distributed under the License is distributed on an "AS IS" BASIS,
REM WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
REM See the License for the specific language governing permissions and
REM limitations under the License.

set ANDROID_HOME="c:\Users\dada\AppData\Local\Android\sdk"
set DEV_HOME="q:\Hack\_PROJ\google_ctf\dex"

javac -encoding utf-8 -verbose -d "%DEV_HOME%\obj" -classpath "%ANDROID_HOME%\platforms\android-19\android.jar" -sourcepath "%DEV_HOME%\src" "%DEV_HOME%\src\com\google\ctf\food\S.java"

%ANDROID_HOME%\build-tools\19.1.0\dx --dex --verbose --output=%DEV_HOME%\bin\classes.dex %DEV_HOME%\obj %DEV_HOME%/lib
