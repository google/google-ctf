<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.10.2" name="crab" tilewidth="59" tileheight="32" tilecount="8" columns="4">
 <image source="crab.png" width="236" height="64"/>
 <tile id="0">
  <properties>
   <property name="animation" value="idle"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="250"/>
  </animation>
 </tile>
 <tile id="1">
  <properties>
   <property name="animation" value="walk"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="250"/>
   <frame tileid="1" duration="250"/>
   <frame tileid="2" duration="250"/>
   <frame tileid="3" duration="250"/>
  </animation>
 </tile>
 <tile id="4">
  <properties>
   <property name="animation" value="shoot"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="6" duration="150"/>
   <frame tileid="4" duration="150"/>
   <frame tileid="5" duration="150"/>
   <frame tileid="4" duration="150"/>
  </animation>
 </tile>
 <tile id="7">
  <properties>
   <property name="animation" value="die"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="7" duration="250"/>
  </animation>
 </tile>
</tileset>
