<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.10.2" name="spikes" tilewidth="35" tileheight="96" tilecount="2" columns="2">
 <image source="key_gate.png" width="70" height="96"/>
 <tile id="0">
  <properties>
   <property name="animation" value="on"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="0" duration="250"/>
  </animation>
 </tile>
 <tile id="1">
  <properties>
   <property name="animation" value="off"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="1" duration="250"/>
  </animation>
 </tile>
</tileset>
