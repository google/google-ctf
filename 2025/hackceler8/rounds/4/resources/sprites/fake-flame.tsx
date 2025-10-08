<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.10.2" name="fake-flame" tilewidth="32" tileheight="48" tilecount="2" columns="2">
 <image source="fake-flame.png" width="64" height="48"/>
 <tile id="0">
  <properties>
   <property name="animation" value="idle"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="250"/>
   <frame tileid="1" duration="250"/>
  </animation>
 </tile>
</tileset>
