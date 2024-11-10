<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.11" tiledversion="1.11.0" name="block" tilewidth="64" tileheight="64" tilecount="2" columns="2">
 <image source="blue_block.png" width="128" height="64"/>
 <tile id="0">
  <properties>
   <property name="animation" value="idle"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="250"/>
  </animation>
 </tile>
 <tile id="1">
  <properties>
   <property name="animation" value="die"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="1" duration="250"/>
  </animation>
 </tile>
</tileset>
