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

<tileset version="1.8" tiledversion="1.8.2" name="sonk" tilewidth="32" tileheight="32" tilecount="48" columns="8">
 <image source="sonk.png" width="256" height="192"/>
 <tile id="0">
  <properties>
   <property name="animation" value="idle"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="125"/>
   <frame tileid="1" duration="125"/>
   <frame tileid="2" duration="125"/>
   <frame tileid="3" duration="125"/>
  </animation>
 </tile>
 <tile id="4">
  <properties>
   <property name="animation" value="brake"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="4" duration="250"/>
   <frame tileid="5" duration="250"/>
  </animation>
 </tile>
 <tile id="8">
  <properties>
   <property name="animation" value="run1"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="8" duration="125"/>
   <frame tileid="9" duration="125"/>
   <frame tileid="10" duration="125"/>
   <frame tileid="11" duration="125"/>
   <frame tileid="12" duration="125"/>
   <frame tileid="13" duration="125"/>
   <frame tileid="14" duration="125"/>
   <frame tileid="15" duration="125"/>
  </animation>
 </tile>
 <tile id="16">
  <properties>
   <property name="animation" value="run2"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="16" duration="125"/>
   <frame tileid="17" duration="125"/>
   <frame tileid="18" duration="125"/>
   <frame tileid="19" duration="125"/>
   <frame tileid="20" duration="125"/>
   <frame tileid="21" duration="125"/>
   <frame tileid="22" duration="125"/>
   <frame tileid="23" duration="125"/>
  </animation>
 </tile>
 <tile id="24">
  <properties>
   <property name="animation" value="run3"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="24" duration="125"/>
   <frame tileid="25" duration="125"/>
   <frame tileid="26" duration="125"/>
   <frame tileid="27" duration="125"/>
   <frame tileid="28" duration="125"/>
   <frame tileid="29" duration="125"/>
   <frame tileid="30" duration="125"/>
   <frame tileid="31" duration="125"/>
  </animation>
 </tile>
 <tile id="32">
  <properties>
   <property name="animation" value="run4"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="32" duration="125"/>
   <frame tileid="33" duration="125"/>
   <frame tileid="34" duration="125"/>
   <frame tileid="35" duration="125"/>
   <frame tileid="36" duration="125"/>
   <frame tileid="37" duration="125"/>
   <frame tileid="38" duration="125"/>
   <frame tileid="39" duration="125"/>
  </animation>
 </tile>
 <tile id="42">
  <properties>
   <property name="animation" value="jump"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="42" duration="63"/>
   <frame tileid="43" duration="63"/>
   <frame tileid="44" duration="63"/>
   <frame tileid="45" duration="63"/>
  </animation>
 </tile>
 <tile id="46">
  <properties>
   <property name="animation" value="damage"/>
  </properties>
  <animation>
   <frame tileid="46" duration="250"/>
   <frame tileid="47" duration="250"/>
  </animation>
 </tile>
</tileset>
