<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.8" tiledversion="1.8.2" name="flameboi-miniboss" tilewidth="24" tileheight="32" tilecount="15" columns="5">
 <image source="flameboi-miniboss.png" width="120" height="96"/>
 <tile id="5">
  <properties>
   <property name="animation" value="idle"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="350"/>
   <frame tileid="1" duration="350"/>
  </animation>
 </tile>
 <tile id="6">
  <properties>
   <property name="animation" value="walk"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="350"/>
   <frame tileid="1" duration="350"/>
  </animation>
 </tile>
 <tile id="8">
  <properties>
   <property name="animation" value="damage"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="9" duration="125"/>
   <frame tileid="0" duration="125"/>
  </animation>
 </tile>
 <tile id="11">
  <properties>
   <property name="animation" value="shoot"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="4" duration="125"/>
   <frame tileid="5" duration="125"/>
   <frame tileid="6" duration="125"/>
   <frame tileid="7" duration="125"/>
   <frame tileid="8" duration="125"/>
   <frame tileid="7" duration="125"/>
   <frame tileid="6" duration="125"/>
   <frame tileid="5" duration="125"/>
   <frame tileid="4" duration="125"/>
  </animation>
 </tile>
 <tile id="12">
  <properties>
   <property name="animation" value="die"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="9" duration="1000"/>
  </animation>
 </tile>
</tileset>
