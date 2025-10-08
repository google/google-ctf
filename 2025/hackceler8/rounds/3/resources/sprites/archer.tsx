<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.10.2" name="archer" tilewidth="32" tileheight="32" tilecount="20" columns="5">
 <image source="archer.png" width="160" height="128"/>
 <tile id="0">
  <properties>
   <property name="animation" value="idle-right"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="1000"/>
  </animation>
 </tile>
 <tile id="1">
  <properties>
   <property name="animation" value="walk-right"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="2" duration="250"/>
   <frame tileid="0" duration="250"/>
   <frame tileid="1" duration="250"/>
   <frame tileid="0" duration="250"/>
  </animation>
 </tile>
 <tile id="2">
  <properties>
   <property name="animation" value="shoot-right"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="3" duration="115"/>
   <frame tileid="4" duration="115"/>
   <frame tileid="5" duration="115"/>
   <frame tileid="6" duration="500"/>
  </animation>
 </tile>
 <tile id="7">
  <properties>
   <property name="animation" value="damage-right"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="7" duration="125"/>
   <frame tileid="0" duration="125"/>
  </animation>
 </tile>
 <tile id="8">
  <properties>
   <property name="animation" value="idle-down"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="8" duration="1000"/>
  </animation>
 </tile>
 <tile id="9">
  <properties>
   <property name="animation" value="walk-down"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="9" duration="250"/>
   <frame tileid="8" duration="250"/>
   <frame tileid="10" duration="250"/>
   <frame tileid="8" duration="250"/>
  </animation>
 </tile>
 <tile id="11">
  <properties>
   <property name="animation" value="shoot-down"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="11" duration="500"/>
   <frame tileid="12" duration="125"/>
   <frame tileid="8" duration="250"/>
  </animation>
 </tile>
 <tile id="13">
  <properties>
   <property name="animation" value="idle-up"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="13" duration="1000"/>
  </animation>
 </tile>
 <tile id="14">
  <properties>
   <property name="animation" value="walk-up"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="14" duration="250"/>
   <frame tileid="13" duration="250"/>
   <frame tileid="15" duration="250"/>
   <frame tileid="13" duration="250"/>
  </animation>
 </tile>
 <tile id="15">
  <properties>
   <property name="animation" value="die"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="18" duration="1000"/>
  </animation>
 </tile>
 <tile id="16">
  <properties>
   <property name="animation" value="shoot-up"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="13" duration="500"/>
   <frame tileid="17" duration="125"/>
   <frame tileid="16" duration="250"/>
  </animation>
 </tile>
 <tile id="18">
  <properties>
   <property name="animation" value="damage-down"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="18" duration="125"/>
   <frame tileid="8" duration="125"/>
  </animation>
 </tile>
 <tile id="19">
  <properties>
   <property name="animation" value="damage-up"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="19" duration="125"/>
   <frame tileid="13" duration="125"/>
  </animation>
 </tile>
</tileset>
