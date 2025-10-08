<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.10.2" name="white-door-v" tilewidth="16" tileheight="48" tilecount="2" columns="2">
 <image source="white-door-v.png" width="32" height="48"/>
 <tile id="0">
  <properties>
   <property name="animation" value="closed"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="1000"/>
  </animation>
 </tile>
 <tile id="1">
  <properties>
   <property name="animation" value="open"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="1" duration="1000"/>
  </animation>
 </tile>
</tileset>
