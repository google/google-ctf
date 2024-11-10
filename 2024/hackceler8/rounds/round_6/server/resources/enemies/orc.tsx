<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.10.2" name="golem" tilewidth="94" tileheight="59" tilecount="12" columns="3">
 <image source="orc.png" width="282" height="236"/>
 <tile id="w">
  <properties>
   <property name="animation" value="walk"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="125"/>
   <frame tileid="1" duration="125"/>
   <frame tileid="2" duration="125"/>
   <frame tileid="3" duration="125"/>
   <frame tileid="4" duration="125"/>
   <frame tileid="5" duration="125"/>
   <frame tileid="6" duration="125"/>
  </animation>
 </tile>
 <tile id="7">
  <properties>
   <property name="animation" value="melee"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="7" duration="125"/>
   <frame tileid="8" duration="125"/>
   <frame tileid="7" duration="125"/>
   <frame tileid="9" duration="500"/>
  </animation>
 </tile>
 <tile id="10">
  <properties>
   <property name="animation" value="idle"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="10" duration="250"/>
  </animation>
 </tile>
 <tile id="11">
  <properties>
   <property name="animation" value="die"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="11" duration="250"/>
  </animation>
 </tile>
</tileset>
