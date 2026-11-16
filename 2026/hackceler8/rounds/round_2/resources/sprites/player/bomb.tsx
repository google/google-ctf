<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.10.2" name="bomb" tilewidth="32" tileheight="32" tilecount="6" columns="2">
 <image source="bomb.png" width="64" height="96"/>
 <tile id="0">
  <properties>
   <property name="animation" value="idle"/>
   <property name="loop" type="bool" value="true"/>
  </properties>  <animation>
   <frame tileid="0" duration="50"/>
   <frame tileid="1" duration="50"/>
  </animation>
 </tile>
 <tile id="2">
  <properties>
   <property name="animation" value="explode"/>
   <property name="loop" type="bool" value="false"/>
  </properties>  <animation>
   <frame tileid="2" duration="100"/>
   <frame tileid="3" duration="100"/>
   <frame tileid="4" duration="100"/>
   <frame tileid="5" duration="100"/>
  </animation>
 </tile>
</tileset>
