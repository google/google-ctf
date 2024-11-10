<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.8" tiledversion="1.8.2" name="snake_lady" tilewidth="172" tileheight="219" tilecount="6" columns="3">
 <image source="snake_lady.png" width="516" height="438"/>
 <tile id="0">
  <properties>
   <property name="animation" value="idle"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="300"/>
   <frame tileid="3" duration="500"/>
   <frame tileid="1" duration="1000"/>
   <frame tileid="3" duration="500"/>
   <frame tileid="0" duration="1000"/>
   <frame tileid="3" duration="500"/>
   <frame tileid="1" duration="1000"/>
   <frame tileid="3" duration="500"/>
   <frame tileid="0" duration="300"/>
   <frame tileid="2" duration="400"/>
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
