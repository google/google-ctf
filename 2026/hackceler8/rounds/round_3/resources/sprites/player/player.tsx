<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.10.2" name="player" tilewidth="40" tileheight="48" tilecount="48" columns="8">
 <image source="player.png" width="320" height="288"/>
 <tile id="0">
  <properties>
   <property name="animation" value="idle"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="1700"/>
   <frame tileid="1" duration="100"/>
   <frame tileid="2" duration="100"/>
   <frame tileid="1" duration="100"/>
  </animation>
 </tile>
 <tile id="3">
  <properties>
   <property name="animation" value="attack"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="3" duration="100"/>
  </animation>
 </tile>
 <tile id="8">
  <properties>
   <property name="animation" value="walk"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="8" duration="166"/>
   <frame tileid="9" duration="166"/>
   <frame tileid="10" duration="166"/>
   <frame tileid="11" duration="166"/>
  </animation>
 </tile>
 <tile id="16">
  <properties>
   <property name="animation" value="jump-up"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="16" duration="300"/>
  </animation>
 </tile>
 <tile id="17">
  <properties>
   <property name="animation" value="jump-down"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="17" duration="100"/>
  </animation>
 </tile>
 <tile id="18">
  <properties>
   <property name="animation" value="damage"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="1" duration="50"/>
   <frame tileid="2" duration="50"/>
   <frame tileid="18" duration="100"/>
   <frame tileid="19" duration="100"/>
   <frame tileid="18" duration="100"/>
   <frame tileid="19" duration="100"/>
  </animation>
 </tile>
 <tile id="19">
  <properties>
   <property name="animation" value="die"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="1" duration="100"/>
   <frame tileid="2" duration="100"/>
   <frame tileid="18" duration="100"/>
   <frame tileid="19" duration="200"/>
   <frame tileid="32" duration="100"/>
  </animation>
 </tile>
 <tile id="24">
  <properties>
   <property name="animation" value="dash"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="24" duration="100"/>
   <frame tileid="25" duration="100"/>
   <frame tileid="26" duration="100"/>
  </animation>
 </tile>
 <tile id="25">
  <properties>
   <property name="animation" value="dash-stop"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="26" duration="100"/>
   <frame tileid="25" duration="100"/>
   <frame tileid="24" duration="100"/>
   <frame tileid="0" duration="100"/>
  </animation>
 </tile>
 <tile id="26">
  <properties>
   <property name="animation" value="wall-jump"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="16" duration="300"/>
  </animation>
 </tile>
 <tile id="27">
  <properties>
   <property name="animation" value="wall-slide"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="27" duration="300"/>
  </animation>
 </tile>
 <tile id="32">
  <properties>
   <property name="animation" value="land"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="16" duration="100"/>
  </animation>
 </tile>
 <tile id="42">
  <properties>
   <property name="animation" value="beam-stop"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="42" duration="100"/>
   <frame tileid="41" duration="100"/>
   <frame tileid="40" duration="100"/>
   <frame tileid="35" duration="100"/>
   <frame tileid="34" duration="100"/>
   <frame tileid="33" duration="100"/>
   <frame tileid="0" duration="100"/>
  </animation>
 </tile>
 <tile id="43">
  <properties>
   <property name="animation" value="beam"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="43" duration="1000"/>
  </animation>
 </tile>
</tileset>
