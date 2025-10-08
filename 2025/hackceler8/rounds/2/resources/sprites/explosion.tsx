<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.10.2" name="explosion" tilewidth="16" tileheight="16" tilecount="5" columns="5">
 <image source="explosion.png" width="80" height="16"/>
 <tile id="0">
  <properties>
   <property name="animation" value="explode"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="0" duration="100"/>
   <frame tileid="1" duration="100"/>
   <frame tileid="2" duration="100"/>
   <frame tileid="3" duration="100"/>
   <frame tileid="4" duration="100"/>
  </animation>
 </tile>
</tileset>
