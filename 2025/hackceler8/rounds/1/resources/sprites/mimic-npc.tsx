<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.10.2" name="mimic_npc" tilewidth="24" tileheight="24" tilecount="3" columns="1">
 <image source="chest-npc.png" width="24" height="72"/>
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
   <property name="animation" value="idle-up"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="1000"/>
  </animation>
 </tile>
 <tile id="2">
  <properties>
   <property name="animation" value="idle-right"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="1000"/>
  </animation>
 </tile>
 <tile id="3">
  <properties>
   <property name="animation" value="open"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="1" duration="1000"/>
  </animation>
 </tile>
 <tile id="4">
  <properties>
   <property name="animation" value="open-mimic"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="2" duration="1000"/>
  </animation>
 </tile>
</tileset>
