<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.8" tiledversion="1.8.2" name="flameboi" tilewidth="24" tileheight="32" tilecount="15" columns="5">
 <image source="flameboi.png" width="120" height="96"/>
 <tile id="0">
  <properties>
   <property name="animation" value="idle-down"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="350"/>
   <frame tileid="1" duration="350"/>
  </animation>
 </tile>
 <tile id="1">
  <properties>
   <property name="animation" value="walk-down"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="350"/>
   <frame tileid="1" duration="350"/>
  </animation>
 </tile>
 <tile id="2">
  <properties>
   <property name="animation" value="idle-up"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="2" duration="350"/>
   <frame tileid="3" duration="350"/>
  </animation>
 </tile>
 <tile id="3">
  <properties>
   <property name="animation" value="walk-up"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="2" duration="350"/>
   <frame tileid="3" duration="350"/>
  </animation>
 </tile>
 <tile id="4">
  <properties>
   <property name="animation" value="shoot-down"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="4" duration="125"/>
   <frame tileid="5" duration="125"/>
   <frame tileid="6" duration="125"/>
   <frame tileid="7" duration="125"/>
   <frame tileid="8" duration="125"/>
   <frame tileid="7" duration="125"/>
   <frame tileid="6" duration="125"/>
   <frame tileid="5" duration="125"/>
   <frame tileid="4" duration="125"/>
  </animation>
 </tile>
 <tile id="5">
  <properties>
   <property name="animation" value="idle-right"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="350"/>
   <frame tileid="1" duration="350"/>
  </animation>
 </tile>
 <tile id="6">
  <properties>
   <property name="animation" value="walk-right"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="350"/>
   <frame tileid="1" duration="350"/>
  </animation>
 </tile>
 <tile id="7">
  <properties>
   <property name="animation" value="damage-up"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="9" duration="125"/>
   <frame tileid="0" duration="125"/>
  </animation>
 </tile>
 <tile id="8">
  <properties>
   <property name="animation" value="damage-right"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="9" duration="125"/>
   <frame tileid="0" duration="125"/>
  </animation>
 </tile>
 <tile id="9">
  <properties>
   <property name="animation" value="damage-down"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="9" duration="125"/>
   <frame tileid="0" duration="125"/>
  </animation>
 </tile>
 <tile id="10">
  <properties>
   <property name="animation" value="shoot-up"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="10" duration="250"/>
   <frame tileid="11" duration="125"/>
   <frame tileid="12" duration="125"/>
   <frame tileid="13" duration="125"/>
   <frame tileid="13" duration="125"/>
   <frame tileid="12" duration="125"/>
   <frame tileid="11" duration="125"/>
   <frame tileid="10" duration="250"/>
  </animation>
 </tile>
 <tile id="11">
  <properties>
   <property name="animation" value="shoot-right"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="4" duration="125"/>
   <frame tileid="5" duration="125"/>
   <frame tileid="6" duration="125"/>
   <frame tileid="7" duration="125"/>
   <frame tileid="8" duration="125"/>
   <frame tileid="7" duration="125"/>
   <frame tileid="6" duration="125"/>
   <frame tileid="5" duration="125"/>
   <frame tileid="4" duration="125"/>
  </animation>
 </tile>
 <tile id="12">
  <properties>
   <property name="animation" value="die"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="9" duration="1000"/>
  </animation>
 </tile>
</tileset>
