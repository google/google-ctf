<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.10.2" name="siren" tilewidth="52" tileheight="60" tilecount="6" columns="3">
 <image source="siren.png" width="156" height="120"/>
 <tile id="0">
  <properties>
   <property name="animation" value="idle"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="250"/>
   <frame tileid="1" duration="250"/>
   <frame tileid="2" duration="250"/>
   <frame tileid="1" duration="250"/>
  </animation>
 </tile>
 <tile id="3">
  <properties>
   <property name="animation" value="melee"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="3" duration="500"/>
   <frame tileid="4" duration="500"/>
  </animation>
 </tile>
 <tile id="5">
  <properties>
   <property name="animation" value="die"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="5" duration="250"/>
  </animation>
 </tile>
</tileset>
