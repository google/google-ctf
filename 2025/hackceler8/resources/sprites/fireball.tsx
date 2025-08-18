<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.8" tiledversion="1.8.2" name="fireball" tilewidth="16" tileheight="16" tilecount="3" columns="3">
 <image source="fireball.png" width="48" height="16"/>
 <tile id="0">
  <properties>
   <property name="animation" value="down"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="250"/>
  </animation>
 </tile>
 <tile id="1">
  <properties>
   <property name="animation" value="right"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="1" duration="250"/>
  </animation>
 </tile>
 <tile id="2">
  <properties>
   <property name="animation" value="diag"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="2" duration="250"/>
  </animation>
 </tile>
</tileset>
