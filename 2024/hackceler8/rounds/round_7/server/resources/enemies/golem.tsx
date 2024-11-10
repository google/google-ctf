<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.10.2" name="golem" tilewidth="48" tileheight="49" tilecount="2" columns="2">
 <image source="golem.png" width="96" height="49"/>
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
