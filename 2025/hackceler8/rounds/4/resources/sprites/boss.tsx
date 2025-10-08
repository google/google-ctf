<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.8" tiledversion="1.8.2" name="player" tilewidth="128" tileheight="96" tilecount="1" columns="1">

 <image source="boss-2.png" width="128" height="96"/>
 <tile id="0">
  <properties>
   <property name="animation" value="damage"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="1000"/>
  </animation>
 </tile>
</tileset>
