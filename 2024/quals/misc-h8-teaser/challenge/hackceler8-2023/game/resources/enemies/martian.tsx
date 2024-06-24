<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.10.2" name="martian" tilewidth="50" tileheight="70" tilecount="10" columns="5">
 <image source="martian.png" width="250" height="140"/>
 <tile id="0">
  <properties>
   <property name="animation" value="shoot"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="250"/>
  </animation>
 </tile>
 <tile id="4">
  <properties>
   <property name="animation" value="idle"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="4" duration="2000"/>
   <frame tileid="3" duration="100"/>
  </animation>
 </tile>
 <tile id="9">
  <properties>
   <property name="animation" value="die"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="9" duration="250"/>
  </animation>
 </tile>
</tileset>
