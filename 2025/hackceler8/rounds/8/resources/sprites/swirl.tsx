<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.11.0" name="swirl" tilewidth="32" tileheight="32" tilecount="6" columns="1">
 <image source="swirl.png" width="32" height="192"/>
 <tile id="0">
  <properties>
   <property name="animation" value="swirl"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="100"/>
   <frame tileid="1" duration="100"/>
   <frame tileid="2" duration="100"/>
  </animation>
 </tile>
 <tile id="3">
  <properties>
   <property name="animation" value="stop"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="3" duration="100"/>
   <frame tileid="4" duration="100"/>
   <frame tileid="5" duration="100"/>
  </animation>
 </tile>
 <tile id="5">
  <properties>
   <property name="animation" value="off"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="5" duration="1000"/>
  </animation>
 </tile>
</tileset>
