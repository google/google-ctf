<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.8" tiledversion="1.8.2" name="charged_shot" tilewidth="32" tileheight="24" tilecount="5" columns="5">
 <image source="charged_shot.png" width="160" height="24"/>
 <tile id="0">
  <properties>
   <property name="animation" value="diag"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="60"/>
   <frame tileid="1" duration="60"/>
  </animation>
 </tile>
 <tile id="1">
  <properties>
   <property name="animation" value="down"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="60"/>
   <frame tileid="1" duration="60"/>
  </animation>
 </tile>
 <tile id="2">
  <properties>
   <property name="animation" value="right"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="60"/>
   <frame tileid="1" duration="60"/>
  </animation>
 </tile>
 <tile id="3">
  <properties>
   <property name="animation" value="explosion"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="2" duration="60"/>
   <frame tileid="3" duration="60"/>
   <frame tileid="4" duration="60"/>
  </animation>
 </tile>
</tileset>
