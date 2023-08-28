<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.10.2" name="AnimationSheet_Mew" tilewidth="48" tileheight="48" tilecount="42" columns="7">
 <image source="AnimationSheet_Mew.png" width="336" height="288"/>
 <tile id="0">
  <properties>
   <property name="animation" value="idle"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="1800"/>
   <frame tileid="5" duration="200"/>
  </animation>
 </tile>
 <tile id="14">
  <properties>
   <property name="animation" value="walk"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="14" duration="100"/>
   <frame tileid="15" duration="100"/>
   <frame tileid="16" duration="100"/>
   <frame tileid="17" duration="100"/>
   <frame tileid="18" duration="100"/>
  </animation>
 </tile>
 <tile id="17">
  <properties>
   <property name="animation" value="run"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="17" duration="200"/>
   <frame tileid="18" duration="200"/>
  </animation>
 </tile>
 <tile id="21">
  <properties>
   <property name="animation" value="jump-down"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="21" duration="200"/>
  </animation>
 </tile>
 <tile id="22">
  <properties>
   <property name="animation" value="jump-up"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="22" duration="200"/>
  </animation>
 </tile>
 <tile id="36">
  <properties>
   <property name="animation" value="die"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="36" duration="200"/>
  </animation>
 </tile>
</tileset>
