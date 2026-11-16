<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.10.2" name="blob-miniboss" tilewidth="32" tileheight="32" tilecount="9" columns="3">
 <image source="blob-miniboss.png" width="96" height="96"/>
 <tile id="2">
  <properties>
   <property name="animation" value="die"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="8" duration="1000"/>
  </animation>
 </tile>
 <tile id="3">
  <properties>
   <property name="animation" value="idle"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="125"/>
   <frame tileid="1" duration="125"/>
   <frame tileid="2" duration="125"/>
   <frame tileid="3" duration="125"/>
   <frame tileid="4" duration="125"/>
   <frame tileid="5" duration="125"/>
   <frame tileid="6" duration="125"/>
   <frame tileid="7" duration="125"/>
  </animation>
 </tile>
 <tile id="6">
  <properties>
   <property name="animation" value="walk"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="125"/>
   <frame tileid="1" duration="125"/>
   <frame tileid="2" duration="125"/>
   <frame tileid="3" duration="125"/>
   <frame tileid="4" duration="125"/>
   <frame tileid="5" duration="125"/>
   <frame tileid="6" duration="125"/>
   <frame tileid="7" duration="125"/>
  </animation>
 </tile>
 <tile id="7">
  <properties>
   <property name="animation" value="damage"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="8" duration="125"/>
   <frame tileid="0" duration="125"/>
  </animation>
 </tile>
</tileset>
