<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.10.2" name="selection" tilewidth="16" tileheight="16" tilecount="4" columns="2">
 <image source="selection.png" width="32" height="32"/>
 <tile id="0">
  <properties>
   <property name="animation" value="flash"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="30"/>
   <frame tileid="1" duration="30"/>
   <frame tileid="2" duration="30"/>
   <frame tileid="3" duration="30"/>
   <frame tileid="2" duration="30"/>
   <frame tileid="1" duration="30"/>
  </animation>
 </tile>
</tileset>
