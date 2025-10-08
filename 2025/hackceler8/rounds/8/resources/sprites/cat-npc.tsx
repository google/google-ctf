<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.10.2" name="cat_npc" tilewidth="16" tileheight="16" tilecount="3" columns="3">
 <image source="cat-npc.png" width="48" height="16"/>
 <tile id="0">
  <properties>
   <property name="animation" value="idle-down"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="1000"/>
  </animation>
 </tile>
 <tile id="1">
  <properties>
   <property name="animation" value="idle-up"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="1" duration="1000"/>
  </animation>
 </tile>
 <tile id="2">
  <properties>
   <property name="animation" value="idle-right"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="2" duration="1000"/>
  </animation>
 </tile>
</tileset>
