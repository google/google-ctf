<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.10.2" name="moving_jellyfish" tilewidth="50" tileheight="50" tilecount="14" columns="7">
 <image source="moving_jellyfish.png" width="350" height="100"/>
 <tile id="0">
  <properties>
   <property name="animation" value="idle"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="1" duration="200"/>
   <frame tileid="2" duration="200"/>
   <frame tileid="3" duration="200"/>
   <frame tileid="4" duration="200"/>
   <frame tileid="5" duration="200"/>
   <frame tileid="6" duration="200"/>
   <frame tileid="7" duration="200"/>
   <frame tileid="8" duration="200"/>
   <frame tileid="9" duration="200"/>
  </animation>
 </tile>
 <tile id="11">
  <properties>
   <property name="animation" value="die"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="11" duration="200"/>
  </animation>
 </tile>
</tileset>
