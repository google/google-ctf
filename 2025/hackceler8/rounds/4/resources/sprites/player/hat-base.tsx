<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.8" tiledversion="1.8.2" name="hat-base" tilewidth="16" tileheight="16" tilecount="8" columns="4">
 <image source="hat-base.png" width="64" height="32"/>
 <tile id="0">
  <properties>
   <property name="animation" value="idle-1"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="1000"/>
  </animation>
 </tile>
 <tile id="1">
  <properties>
   <property name="animation" value="idle-2"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="1" duration="1000"/>
  </animation>
 </tile>
 <tile id="2">
  <properties>
   <property name="animation" value="idle-3"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="2" duration="1000"/>
  </animation>
 </tile>
 <tile id="3">
  <properties>
   <property name="animation" value="idle-4"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="3" duration="1000"/>
  </animation>
 </tile>
 <tile id="4">
  <properties>
   <property name="animation" value="damage-1"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="4" duration="125"/>
   <frame tileid="0" duration="125"/>
  </animation>
 </tile>
 <tile id="5">
  <properties>
   <property name="animation" value="damage-2"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="5" duration="125"/>
   <frame tileid="1" duration="125"/>
  </animation>
 </tile>
 <tile id="6">
  <properties>
   <property name="animation" value="damage-3"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="6" duration="125"/>
   <frame tileid="2" duration="125"/>
  </animation>
 </tile>
 <tile id="7">
  <properties>
   <property name="animation" value="damage-4"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="7" duration="125"/>
   <frame tileid="3" duration="125"/>
  </animation>
 </tile>
</tileset>
