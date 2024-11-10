<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.10.2" name="Chest" tilewidth="32" tileheight="32" tilecount="2" columns="2">
 <image source="chest2.png" width="64" height="32"/>
 <tile id="0">
  <properties>
   <property name="animation" value="closed"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="0" duration="100"/>
  </animation>
 </tile>
 <tile id="1">
  <properties>
   <property name="animation" value="open"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="1" duration="100"/>
  </animation>
 </tile>
</tileset>
