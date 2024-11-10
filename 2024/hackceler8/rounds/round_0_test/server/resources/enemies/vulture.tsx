<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.10.2" name="vulture" tilewidth="56" tileheight="47" tilecount="9" columns="3">
 <image source="vulture.png" width="168" height="141"/>
 <tile id="0">
  <properties>
   <property name="animation" value="idle"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="125"/>
   <frame tileid="1" duration="125"/>
   <frame tileid="0" duration="125"/>
   <frame tileid="2" duration="125"/>
   <frame tileid="3" duration="125"/>
   <frame tileid="2" duration="125"/>
  </animation>
 </tile>
 <tile id="4">
  <properties>
   <property name="animation" value="shoot"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="4" duration="250"/>
   <frame tileid="5" duration="250"/>
  </animation>
 </tile>
 <tile id="6">
  <properties>
   <property name="animation" value="die"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="6" duration="250"/>
  </animation>
 </tile>
</tileset>
