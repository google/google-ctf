<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.10.2" name="boss-hand" tilewidth="48" tileheight="32" tilecount="3" columns="1">
 <image source="boss-hand.png" width="48" height="96"/>
 <tile id="0">
  <properties>
   <property name="animation" value="idle"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="1000"/>
  </animation>
 </tile>
 <tile id="1">
  <properties>
   <property name="animation" value="shoot"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="1" duration="1000"/>
  </animation>
 </tile>
 <tile id="2">
  <properties>
   <property name="animation" value="walk"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="1000"/>
  </animation>
 </tile>
 <tile id="3">
  <properties>
   <property name="animation" value="die"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="2" duration="1000"/>
  </animation>
 </tile>
 <tile id="4">
  <properties>
   <property name="animation" value="damage"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="2" duration="125"/>
   <frame tileid="0" duration="125"/>
  </animation>
 </tile>
</tileset>
