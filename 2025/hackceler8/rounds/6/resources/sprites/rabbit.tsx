<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.10.2" name="rabbit" tilewidth="24" tileheight="24" tilecount="12" columns="4">
 <image source="rabbit.png" width="96" height="72"/>
 <tile id="0">
  <properties>
   <property name="animation" value="idle-down"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="1000"/>
  </animation>
 </tile>
 <tile id="1">
  <properties>
   <property name="animation" value="walk-down"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="180"/>
   <frame tileid="2" duration="180"/>
   <frame tileid="1" duration="180"/>
  </animation>
 </tile>
 <tile id="3">
  <properties>
   <property name="animation" value="damage-down"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="3" duration="250"/>
   <frame tileid="0" duration="250"/>
  </animation>
 </tile>
 <tile id="4">
  <properties>
   <property name="animation" value="idle-right"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="4" duration="1000"/>
  </animation>
 </tile>
 <tile id="5">
  <properties>
   <property name="animation" value="walk-right"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="4" duration="180"/>
   <frame tileid="6" duration="180"/>
   <frame tileid="5" duration="180"/>
  </animation>
 </tile>
 <tile id="7">
  <properties>
   <property name="animation" value="damage-right"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="7" duration="250"/>
   <frame tileid="4" duration="250"/>
  </animation>
 </tile>
 <tile id="8">
  <properties>
   <property name="animation" value="idle-up"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="8" duration="1000"/>
  </animation>
 </tile>
 <tile id="9">
  <properties>
   <property name="animation" value="walk-up"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="8" duration="180"/>
   <frame tileid="10" duration="180"/>
   <frame tileid="9" duration="180"/>
  </animation>
 </tile>
 <tile id="10">
  <properties>
   <property name="animation" value="die"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="3" duration="1000"/>
  </animation>
 </tile>
 <tile id="11">
  <properties>
   <property name="animation" value="damage-up"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="11" duration="250"/>
   <frame tileid="8" duration="250"/>
  </animation>
 </tile>
</tileset>
