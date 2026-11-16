<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.10.2" name="player-melee" tilewidth="40" tileheight="48" tilecount="32" columns="4">
 <image source="player-melee.png" width="160" height="384"/>
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
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="24" duration="170"/>
   <frame tileid="3" duration="60"/>
   <frame tileid="25" duration="270"/>
  </animation>
 </tile>
 <tile id="4">
  <properties>
   <property name="animation" value="walk"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="4" duration="166"/>
   <frame tileid="5" duration="166"/>
   <frame tileid="6" duration="166"/>
   <frame tileid="7" duration="166"/>
  </animation>
 </tile>
 <tile id="8">
  <properties>
   <property name="animation" value="jump-up"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="8" duration="300"/>
  </animation>
 </tile>
 <tile id="9">
  <properties>
   <property name="animation" value="jump-down"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="9" duration="100"/>
  </animation>
 </tile>
 <tile id="10">
  <properties>
   <property name="animation" value="damage"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="1" duration="50"/>
   <frame tileid="2" duration="50"/>
   <frame tileid="10" duration="100"/>
   <frame tileid="11" duration="100"/>
   <frame tileid="10" duration="100"/>
   <frame tileid="11" duration="100"/>
  </animation>
 </tile>
 <tile id="11">
  <properties>
   <property name="animation" value="die"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="1" duration="100"/>
   <frame tileid="2" duration="100"/>
   <frame tileid="10" duration="100"/>
   <frame tileid="11" duration="200"/>
   <frame tileid="16" duration="100"/>
  </animation>
 </tile>
 <tile id="12">
  <properties>
   <property name="animation" value="dash"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="12" duration="100"/>
   <frame tileid="13" duration="100"/>
   <frame tileid="14" duration="100"/>
  </animation>
 </tile>
 <tile id="13">
  <properties>
   <property name="animation" value="dash-stop"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="14" duration="100"/>
   <frame tileid="13" duration="100"/>
   <frame tileid="12" duration="100"/>
   <frame tileid="0" duration="100"/>
  </animation>
 </tile>
 <tile id="14">
  <properties>
   <property name="animation" value="wall-jump"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="8" duration="300"/>
  </animation>
 </tile>
 <tile id="15">
  <properties>
   <property name="animation" value="wall-slide"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="15" duration="300"/>
  </animation>
 </tile>
 <tile id="16">
  <properties>
   <property name="animation" value="land"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="8" duration="100"/>
  </animation>
 </tile>
 <tile id="22">
  <properties>
   <property name="animation" value="beam-stop"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="22" duration="100"/>
   <frame tileid="21" duration="100"/>
   <frame tileid="20" duration="100"/>
   <frame tileid="19" duration="100"/>
   <frame tileid="18" duration="100"/>
   <frame tileid="17" duration="100"/>
   <frame tileid="0" duration="100"/>
  </animation>
 </tile>
 <tile id="23">
  <properties>
   <property name="animation" value="beam"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="23" duration="1000"/>
  </animation>
 </tile>
 <tile id="28">
  <properties>
   <property name="animation" value="zjump-attack"/>
   <property name="loop" type="bool" value="false"/>
  </properties>
  <animation>
   <frame tileid="29" duration="160"/>
   <frame tileid="28" duration="60"/>
   <frame tileid="30" duration="270"/>
  </animation>
 </tile>
</tileset>
