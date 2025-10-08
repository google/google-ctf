<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.8" tiledversion="1.8.2" name="player-base" tilewidth="16" tileheight="24" tilecount="20" columns="5">
 <image source="player-base.png" width="80" height="96"/>
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
   <frame tileid="0" duration="250"/>
   <frame tileid="1" duration="250"/>
   <frame tileid="0" duration="250"/>
   <frame tileid="3" duration="250"/>
  </animation>
 </tile>
 <tile id="2">
  <properties>
   <property name="animation" value="damage-down"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="2" duration="125"/>
   <frame tileid="0" duration="125"/>
  </animation>
 </tile>
 <tile id="4">
  <properties>
   <property name="animation" value="fall"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="18" duration="250"/>
   <frame tileid="4" duration="250"/>
   <frame tileid="9" duration="250"/>
   <frame tileid="14" duration="250"/>
   <frame tileid="19" duration="250"/>
  </animation>
 </tile>
 <tile id="5">
  <properties>
   <property name="animation" value="idle-right"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="5" duration="1000"/>
  </animation>
 </tile>
 <tile id="6">
  <properties>
   <property name="animation" value="walk-right"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="5" duration="250"/>
   <frame tileid="6" duration="250"/>
   <frame tileid="5" duration="250"/>
   <frame tileid="8" duration="250"/>
  </animation>
 </tile>
 <tile id="7">
  <properties>
   <property name="animation" value="damage-right"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="7" duration="125"/>
   <frame tileid="5" duration="125"/>
  </animation>
 </tile>
 <tile id="10">
  <properties>
   <property name="animation" value="idle-up"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="10" duration="1000"/>
  </animation>
 </tile>
 <tile id="11">
  <properties>
   <property name="animation" value="walk-up"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="10" duration="250"/>
   <frame tileid="11" duration="250"/>
   <frame tileid="10" duration="250"/>
   <frame tileid="13" duration="250"/>
  </animation>
 </tile>
 <tile id="12">
  <properties>
   <property name="animation" value="damage-up"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="12" duration="125"/>
   <frame tileid="10" duration="125"/>
  </animation>
 </tile>
 <tile id="15">
  <properties>
   <property name="animation" value="attack-down"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="15" duration="1000"/>
  </animation>
 </tile>
 <tile id="16">
  <properties>
   <property name="animation" value="attack-right"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="16" duration="1000"/>
  </animation>
 </tile>
 <tile id="17">
  <properties>
   <property name="animation" value="attack-up"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="17" duration="1000"/>
  </animation>
 </tile>
 <tile id="18">
  <properties>
   <property name="animation" value="die"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="18" duration="1000"/>
  </animation>
 </tile>
</tileset>
