<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.8" tiledversion="1.8.2" name="simple_shot" tilewidth="16" tileheight="16" tilecount="4" columns="4">
 <image source="simple_shot.png" width="64" height="16"/>
 <tile id="0">
  <properties>
   <property name="animation" value="diag"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="100"/>
  </animation>
 </tile>
 <tile id="1">
  <properties>
   <property name="animation" value="down"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="100"/>
  </animation>
 </tile>
 <tile id="2">
  <properties>
   <property name="animation" value="right"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="100"/>
  </animation>
 </tile>
 <tile id="3">
  <properties>
   <property name="animation" value="explosion"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="1" duration="60"/>
   <frame tileid="2" duration="60"/>
   <frame tileid="3" duration="60"/>
  </animation>
 </tile>
</tileset>
