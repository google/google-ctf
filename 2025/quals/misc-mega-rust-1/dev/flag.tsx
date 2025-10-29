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

<tileset version="1.8" tiledversion="1.8.2" name="flag" tilewidth="16" tileheight="16" tilecount="6" columns="3">
 <image source="flag.png" width="48" height="32"/>
 <tile id="0">
  <properties>
   <property name="animation" value="flag"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="125"/>
   <frame tileid="1" duration="125"/>
   <frame tileid="2" duration="125"/>
   <frame tileid="3" duration="125"/>
   <frame tileid="4" duration="125"/>
   <frame tileid="5" duration="125"/>
  </animation>
 </tile>
</tileset>
