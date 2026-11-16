<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.10.2" name="player-sword" tilewidth="64" tileheight="72" tilecount="8" columns="4">
 <image source="player-sword.png" width="256" height="144"/>
 <tile id="0">
  <properties>
   <property name="animation" value="slash"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="7" duration="70"/>
   <frame tileid="0" duration="50"/>
   <frame tileid="1" duration="50"/>
   <frame tileid="2" duration="50"/>
   <frame tileid="3" duration="50"/>
   <frame tileid="4" duration="100"/>
   <frame tileid="5" duration="50"/>
   <frame tileid="6" duration="50"/>
   <frame tileid="7" duration="50"/>
  </animation>
 </tile>
 <tile id="7">
  <properties>
   <property name="animation" value="off"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="7" duration="100"/>
  </animation>
 </tile>
</tileset>
