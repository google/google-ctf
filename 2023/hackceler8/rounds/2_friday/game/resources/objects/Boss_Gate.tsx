<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.10.2" name="Boss_Gate" tilewidth="290" tileheight="274" tilecount="2" columns="1">
 <image source="Boss_Gate.png" width="290" height="548"/>
 <tile id="0">
  <properties>
   <property name="animation" value="on"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="250"/>
  </animation>
 </tile>
 <tile id="1">
  <properties>
   <property name="animation" value="off"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="1" duration="250"/>
  </animation>
 </tile>
</tileset>
