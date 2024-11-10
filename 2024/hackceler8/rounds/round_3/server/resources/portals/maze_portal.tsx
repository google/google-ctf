<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.10.2" name="maze_portal" tilewidth="85" tileheight="85" tilecount="2" columns="1">
 <image source="maze_portal.png" width="85" height="170"/>
 <tile id="0">
  <properties>
   <property name="animation" value="portal"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="300"/>
   <frame tileid="1" duration="300"/>
  </animation>
 </tile>
</tileset>
