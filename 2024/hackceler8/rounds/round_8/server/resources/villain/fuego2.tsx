<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.10.2" name="fuego-2" tilewidth="344" tileheight="219" tilecount="20" columns="4">
 <image source="fuego-2.png" width="1376" height="1095"/>
 <tile id="0">
  <properties>
   <property name="animation" value="idle"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="250"/>
  </animation>
 </tile>
 <tile id="1">
  <properties>
   <property name="animation" value="point"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="1" duration="250"/>
  </animation>
 </tile>
 <tile id="2">
  <properties>
   <property name="animation" value="walk"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="2" duration="250"/>
   <frame tileid="3" duration="250"/>
   <frame tileid="4" duration="250"/>
   <frame tileid="5" duration="250"/>
   <frame tileid="6" duration="250"/>
   <frame tileid="7" duration="250"/>
  </animation>
 </tile>
 <tile id="8">
  <properties>
   <property name="animation" value="slash"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="8" duration="125"/>
   <frame tileid="9" duration="125"/>
   <frame tileid="10" duration="125"/>
   <frame tileid="11" duration="125"/>
  </animation>
 </tile>
 <tile id="9">
  <properties>
   <property name="animation" value="jump"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="8" duration="125"/>
  </animation>
 </tile>
 <tile id="12">
  <properties>
   <property name="animation" value="disappear"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="12" duration="125"/>
   <frame tileid="13" duration="125"/>
   <frame tileid="14" duration="125"/>
   <frame tileid="15" duration="125"/>
  </animation>
 </tile>
 <tile id="13">
  <properties>
   <property name="animation" value="appear"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="15" duration="125"/>
   <frame tileid="14" duration="125"/>
   <frame tileid="13" duration="125"/>
   <frame tileid="12" duration="125"/>
  </animation>
 </tile>
 <tile id="16">
  <properties>
   <property name="animation" value="die"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="16" duration="250"/>
  </animation>
 </tile>
</tileset>
