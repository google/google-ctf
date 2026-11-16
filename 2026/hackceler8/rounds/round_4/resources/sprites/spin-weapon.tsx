<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.11.0" name="spin-weapon" tilewidth="24" tileheight="24" tilecount="3" columns="3">
 <image source="spin-weapon.png" width="72" height="24"/>
 <tile id="0">
  <properties>
   <property name="animation" value="spin"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="50"/>
   <frame tileid="1" duration="50"/>
   <frame tileid="2" duration="50"/>
  </animation>
 </tile>
</tileset>
