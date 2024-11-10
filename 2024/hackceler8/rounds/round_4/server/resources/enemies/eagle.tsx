<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.10.2" name="eagle" tilewidth="59" tileheight="67" tilecount="14" columns="7">
 <image source="eagle.png" width="413" height="134"/>
 <tile id="0">
  <properties>
   <property name="animation" value="idle"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="125"/>
   <frame tileid="1" duration="125"/>
   <frame tileid="2" duration="125"/>
   <frame tileid="3" duration="125"/>
   <frame tileid="2" duration="125"/>
   <frame tileid="1" duration="125"/>
   <frame tileid="4" duration="125"/>
   <frame tileid="5" duration="125"/>
   <frame tileid="6" duration="125"/>
   <frame tileid="7" duration="125"/>
   <frame tileid="6" duration="125"/>
   <frame tileid="5" duration="125"/>
  </animation>
 </tile>
 <tile id="8">
  <properties>
   <property name="animation" value="melee"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="10" duration="200"/>
   <frame tileid="9" duration="200"/>
   <frame tileid="8" duration="200"/>
  </animation>
 </tile>
 <tile id="11">
  <properties>
   <property name="animation" value="die"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="11" duration="250"/>
  </animation>
 </tile>
</tileset>
