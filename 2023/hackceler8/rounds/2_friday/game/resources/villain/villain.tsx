<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.10.2" name="villain" tilewidth="600" tileheight="600" tilecount="36" columns="6">
 <image source="villain.png" width="3600" height="3600"/>
 <tile id="0">
  <properties>
   <property name="animation" value="damage"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="250"/>
  </animation>
 </tile>
 <tile id="1">
  <properties>
   <property name="animation" value="blank"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="1" duration="250"/>
  </animation>
 </tile>
 <tile id="11">
  <properties>
   <property name="animation" value="battery"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="6" duration="100"/>
   <frame tileid="11" duration="250"/>
  </animation>
 </tile>
 <tile id="17">
  <properties>
   <property name="animation" value="crack"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="6" duration="100"/>
   <frame tileid="17" duration="300"/>
   <frame tileid="35" duration="300"/>
  </animation>
 </tile>
 <tile id="23">
  <properties>
   <property name="animation" value="ohno"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="6" duration="100"/>
   <frame tileid="23" duration="300"/>
   <frame tileid="35" duration="300"/>
  </animation>
 </tile>
 <tile id="29">
  <properties>
   <property name="animation" value="bwahaha"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="6" duration="100"/>
   <frame tileid="29" duration="250"/>
  </animation>
</tile>
 <tile id="30">
  <properties>
   <property name="animation" value="bwahaha2"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="29" duration="250"/>
  </animation>
 </tile>
</tileset>
