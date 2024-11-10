<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.10.2" name="Domino" tilewidth="53" tileheight="53" tilecount="16" columns="4">
 <image source="Domino.png" width="212" height="212"/>
 <tile id="0">
  <properties>
   <property name="animation" value="idle"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="1000"/>
   <frame tileid="1" duration="250"/>
   <frame tileid="2" duration="250"/>
   <frame tileid="1" duration="250"/>
  </animation>
 </tile>
 <tile id="2">
  <properties>
   <property name="animation" value="walk"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="3" duration="250"/>
   <frame tileid="4" duration="250"/>
  </animation>
 </tile>
 <tile id="3">
  <properties>
   <property name="animation" value="run"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="3" duration="250"/>
   <frame tileid="4" duration="250"/>
  </animation>
 </tile>
 <tile id="5">
  <properties>
   <property name="animation" value="jump-up"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="5" duration="250"/>
  </animation>
 </tile>
 <tile id="6">
  <properties>
   <property name="animation" value="jump-down"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="6" duration="250"/>
  </animation>
 </tile>
 <tile id="7">
  <properties>
   <property name="animation" value="damage"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="7" duration="250"/>
  </animation>
 </tile>
 <tile id="8">
  <properties>
   <property name="animation" value="die"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="8" duration="250"/>
  </animation>
 </tile>
 <tile id="9">
  <properties>
   <property name="animation" value="crouch"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="9" duration="250"/>
  </animation>
 </tile>
 <tile id="10">
  <properties>
   <property name="animation" value="melee"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="10" duration="75"/>
   <frame tileid="11" duration="75"/>
   <frame tileid="14" duration="75"/>
   <frame tileid="15" duration="75"/>
  </animation>
 </tile>
</tileset>
