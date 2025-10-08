<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.10.2" name="green-door-h" tilewidth="48" tileheight="16" tilecount="2" columns="1">
 <image source="green-door-h.png" width="48" height="32"/>
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
