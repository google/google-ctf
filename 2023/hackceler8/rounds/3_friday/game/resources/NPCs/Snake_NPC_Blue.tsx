<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.8" tiledversion="1.8.2" name="npc1" tilewidth="100" tileheight="54" tilecount="16" columns="8">
 <image source="Snake_NPC_Blue.png" width="800" height="108"/>
 <tile id="0">
  <properties>
   <property name="animation" value="idle-front"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="250"/>
  </animation>
 </tile>
 <tile id="1">
  <properties>
   <property name="animation" value="idle-back"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="1" duration="250"/>
  </animation>
 </tile>
 <tile id="2">
  <properties>
   <property name="animation" value="idle-left"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="2" duration="250"/>
  </animation>
 </tile>
 <tile id="3">
  <properties>
   <property name="animation" value="walk-left"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="2" duration="100"/>
   <frame tileid="3" duration="100"/>
   <frame tileid="4" duration="100"/>
   <frame tileid="5" duration="100"/>
   <frame tileid="6" duration="100"/>
   <frame tileid="7" duration="100"/>
  </animation>
 </tile>
 <tile id="8">
  <properties>
   <property name="animation" value="walk-front"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="250"/>
  </animation>
 </tile>
 <tile id="9">
  <properties>
   <property name="animation" value="walk-back"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="1" duration="250"/>
  </animation>
 </tile>
 <tile id="10">
  <properties>
   <property name="animation" value="idle-right"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="10" duration="250"/>
  </animation>
 </tile>
 <tile id="11">
  <properties>
   <property name="animation" value="walk-right"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="15" duration="100"/>
   <frame tileid="14" duration="100"/>
   <frame tileid="13" duration="100"/>
   <frame tileid="12" duration="100"/>
   <frame tileid="11" duration="100"/>
   <frame tileid="10" duration="100"/>
  </animation>
 </tile>
</tileset>
