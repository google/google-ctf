<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.10.2" name="boss_gate" tilewidth="120" tileheight="104" tilecount="8" columns="2">
 <image source="boss_gate.png" width="240" height="416"/>
 <tile id="0">
  <properties>
   <property name="animation" value="off"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="0" duration="250"/>
  </animation>
 </tile>
 <tile id="3">
  <properties>
   <property name="animation" value="on"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="0" duration="250"/>
   <frame tileid="1" duration="250"/>
   <frame tileid="2" duration="250"/>
   <frame tileid="3" duration="250"/>
   <frame tileid="4" duration="250"/>
   <frame tileid="5" duration="250"/>
   <frame tileid="6" duration="250"/>
   <frame tileid="7" duration="250"/>
  </animation>
 </tile>
</tileset>
