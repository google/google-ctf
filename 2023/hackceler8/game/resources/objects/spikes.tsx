<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.10.2" name="spikes" tilewidth="64" tileheight="64" tilecount="5" columns="5">
 <image source="spikes.png" width="320" height="64"/>
 <tile id="0">
  <properties>
   <property name="animation" value="on"/>
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
 <tile id="4">
  <properties>
   <property name="animation" value="off"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="4" duration="100"/>
   <frame tileid="3" duration="100"/>
   <frame tileid="2" duration="100"/>
   <frame tileid="0" duration="100"/>
  </animation>
 </tile>
</tileset>
