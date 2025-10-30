<?xml version="1.0" encoding="UTF-8"?>
/**
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

<tileset version="1.8" tiledversion="1.8.2" name="spike" tilewidth="24" tileheight="24" tilecount="3" columns="3">
 <image source="spike.png" width="72" height="24"/>
 <tile id="0">
  <animation>
   <frame tileid="0" duration="2000"/>
   <frame tileid="1" duration="75"/>
   <frame tileid="2" duration="150"/>
   <frame tileid="1" duration="75"/>
  </animation>
 </tile>
</tileset>
