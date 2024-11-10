<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.10.2" name="octopus" tilewidth="52" tileheight="50" tilecount="6" columns="3">
 <image source="octopus.png" width="156" height="100"/>
 <tile id="0">
  <properties>
   <property name="animation" value="idle"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="500"/>
   <frame tileid="3" duration="500"/>
  </animation>
 </tile>
 <tile id="2">
  <properties>
   <property name="animation" value="shoot"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="1" duration="50"/>
   <frame tileid="2" duration="125"/>
  </animation>
 </tile>
 <tile id="4">
  <properties>
   <property name="animation" value="die"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="4" duration="250"/>
  </animation>
 </tile>
</tileset>
