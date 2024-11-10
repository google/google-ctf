<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.10.2" name="arcade_box" tilewidth="50" tileheight="66" tilecount="5" columns="5">
 <image source="arcade_box.png" width="250" height="66"/>
 <tile id="0">
  <properties>
   <property name="animation" value="off"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="250"/>
  </animation>
 </tile>
 <tile id="1">
  <properties>
   <property name="animation" value="on"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="0" duration="125"/>
   <frame tileid="1" duration="125"/>
   <frame tileid="2" duration="125"/>
   <frame tileid="3" duration="125"/>
   <frame tileid="4" duration="125"/>
  </animation>
 </tile>
 <tile id="2">
  <properties>
   <property name="animation" value="turn-off"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="4" duration="125"/>
   <frame tileid="3" duration="125"/>
   <frame tileid="2" duration="125"/>
   <frame tileid="1" duration="125"/>
   <frame tileid="0" duration="125"/>
  </animation>
 </tile>
</tileset>
