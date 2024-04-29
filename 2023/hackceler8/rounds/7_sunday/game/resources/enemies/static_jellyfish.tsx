<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.10.2" name="static_jellyfish" tilewidth="250" tileheight="270" tilecount="12" columns="4">
 <image source="static_jellyfish.png" width="1000" height="810"/>
 <tile id="0">
  <properties>
   <property name="animation" value="shock"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="250"/>
   <frame tileid="1" duration="250"/>
   <frame tileid="2" duration="250"/>
   <frame tileid="3" duration="250"/>
   <frame tileid="4" duration="250"/>
  </animation>
 </tile>
 <tile id="5">
  <properties>
   <property name="animation" value="idle"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="5" duration="250"/>
   <frame tileid="6" duration="250"/>
   <frame tileid="7" duration="250"/>
   <frame tileid="8" duration="250"/>
   <frame tileid="9" duration="250"/>
  </animation>
 </tile>
 <tile id="10">
  <properties>
   <property name="animation" value="die"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="10" duration="250"/>
  </animation>
 </tile>
</tileset>
