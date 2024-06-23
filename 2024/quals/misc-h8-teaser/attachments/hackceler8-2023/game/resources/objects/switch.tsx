<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.10.2" name="switch" tilewidth="32" tileheight="32" tilecount="2" columns="2">
 <image source="switch.png" width="64" height="32"/>
 <tile id="0">
  <properties>
   <property name="animation" value="off"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="200"/>
  </animation>
 </tile>
 <tile id="1">
  <properties>
   <property name="animation" value="on"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="1" duration="200"/>
  </animation>
 </tile>
</tileset>
