<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.10.2" name="rabbit-miniboss" tilewidth="24" tileheight="24" tilecount="4" columns="4">
 <image source="rabbit-miniboss.png" width="96" height="24"/>
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
   <property name="animation" value="walk"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="180"/>
   <frame tileid="2" duration="180"/>
   <frame tileid="1" duration="180"/>
  </animation>
 </tile>
 <tile id="3">
  <properties>
   <property name="animation" value="damage"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="3" duration="250"/>
   <frame tileid="0" duration="250"/>
  </animation>
 </tile>
 <tile id="10">
  <properties>
   <property name="animation" value="die"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="3" duration="1000"/>
  </animation>
 </tile>
</tileset>
