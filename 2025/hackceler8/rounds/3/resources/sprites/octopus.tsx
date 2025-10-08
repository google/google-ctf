<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.10.2" name="octopus" tilewidth="32" tileheight="32" tilecount="4" columns="4">
 <image source="octopus.png" width="128" height="32"/>
 <tile id="0">
  <properties>
   <property name="animation" value="idle-down"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="250"/>
   <frame tileid="1" duration="250"/>
   <frame tileid="2" duration="250"/>
   <frame tileid="1" duration="250"/>
  </animation>
 </tile>
 <tile id="1">
  <properties>
   <property name="animation" value="walk-down"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="250"/>
   <frame tileid="1" duration="250"/>
   <frame tileid="2" duration="250"/>
   <frame tileid="1" duration="250"/>
  </animation>
 </tile>
 <tile id="2">
  <properties>
   <property name="animation" value="damage-down"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="3" duration="125"/>
   <frame tileid="0" duration="125"/>
  </animation>
 </tile>
 <tile id="3">
  <properties>
   <property name="animation" value="idle-right"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="250"/>
   <frame tileid="1" duration="250"/>
   <frame tileid="2" duration="250"/>
   <frame tileid="1" duration="250"/>
  </animation>
 </tile>
 <tile id="4">
  <properties>
   <property name="animation" value="walk-right"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="250"/>
   <frame tileid="1" duration="250"/>
   <frame tileid="2" duration="250"/>
   <frame tileid="1" duration="250"/>
  </animation>
 </tile>
 <tile id="5">
  <properties>
   <property name="animation" value="damage-right"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="3" duration="125"/>
   <frame tileid="0" duration="125"/>
  </animation>
 </tile>
 <tile id="6">
  <properties>
   <property name="animation" value="damage-up"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="3" duration="125"/>
   <frame tileid="0" duration="125"/>
  </animation>
 </tile>
 <tile id="7">
  <properties>
   <property name="animation" value="idle-up"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="250"/>
   <frame tileid="1" duration="250"/>
   <frame tileid="2" duration="250"/>
   <frame tileid="1" duration="250"/>
  </animation>
 </tile>
 <tile id="8">
  <properties>
   <property name="animation" value="walk-up"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="250"/>
   <frame tileid="1" duration="250"/>
   <frame tileid="2" duration="250"/>
   <frame tileid="1" duration="250"/>
  </animation>
 </tile>
 <tile id="9">
  <properties>
   <property name="animation" value="die"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="3" duration="1000"/>
  </animation>
 </tile>
</tileset>
