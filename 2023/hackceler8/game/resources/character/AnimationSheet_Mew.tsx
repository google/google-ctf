<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.10.2" name="AnimationSheet_Mew" tilewidth="48" tileheight="48" tilecount="18" columns="6">
 <image source="AnimationSheet_Mew.png" width="384" height="96"/>
 <tile id="0">
  <properties>
   <property name="animation" value="idle"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="200"/>
   <frame tileid="1" duration="200"/>
   <frame tileid="3" duration="200"/>
   <frame tileid="1" duration="200"/>
   <frame tileid="0" duration="500"/>
   <frame tileid="4" duration="200"/>
   <frame tileid="5" duration="200"/>
   <frame tileid="6" duration="200"/>
   <frame tileid="5" duration="200"/>
   <frame tileid="4" duration="200"/>
  </animation>
 </tile>
 <tile id="1">
  <properties>
   <property name="animation" value="walk"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="7" duration="50"/>
   <frame tileid="8" duration="100"/>
   <frame tileid="9" duration="100"/>
   <frame tileid="12" duration="100"/>
   <frame tileid="10" duration="100"/>
   <frame tileid="11" duration="100"/>
  </animation>
 </tile>
 <tile id="2">
  <properties>
   <property name="animation" value="run"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
  <frame tileid="7" duration="50"/>
   <frame tileid="8" duration="100"/>
   <frame tileid="9" duration="100"/>
   <frame tileid="12" duration="100"/>
   <frame tileid="10" duration="100"/>
   <frame tileid="11" duration="100"/>
  </animation>
 </tile>
 <tile id="13">
  <properties>
   <property name="animation" value="jump-down"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="13" duration="200"/>
  </animation>
 </tile>
 <tile id="12">
  <properties>
   <property name="animation" value="jump-up"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="12" duration="200"/>
  </animation>
 </tile>
 <tile id="14">
  <properties>
   <property name="animation" value="die"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="1" duration="200"/>
  </animation>
 </tile>
</tileset>
