<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.10.2" name="Fire" tilewidth="32" tileheight="32" tilecount="3" columns="3">
 <image source="weet.png" width="96" height="32"/>
 <tile id="0">
  <properties>
   <property name="animation" value="idle"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="125"/>
   <frame tileid="1" duration="125"/>
   <frame tileid="2" duration="125"/>
  </animation>
 </tile>
 <tile id="2">
  <properties>
   <property name="animation" value="stage_0"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="250"/>
  </animation>
      </tile>
<tile id="3">
  <properties>
   <property name="animation" value="stage_1"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="1" duration="250"/>
  </animation>
 </tile>
<tile id="4">
  <properties>
   <property name="animation" value="stage_2"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="2" duration="250"/>
  </animation>
 </tile>
</tileset>
