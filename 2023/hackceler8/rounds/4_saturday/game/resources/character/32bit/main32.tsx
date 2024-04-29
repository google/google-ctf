<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.10.1" name="main2" tilewidth="16" tileheight="16" tilecount="1" columns="1">
 <image source="main32.PNG" width="16" height="16"/>
 <tile id="0">
  <properties>
   <property name="animation" value="idle"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="500"/>
   <frame tileid="0" duration="500"/>
  </animation>
 </tile>
 <tile id="1">
  <properties>
   <property name="animation" value="walk"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="500"/>
   <frame tileid="0" duration="500"/>
  </animation>
 </tile>
</tileset>
