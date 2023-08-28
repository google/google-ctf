<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.10.1" name="AnimationSheet_OverheadMew" tilewidth="32" tileheight="48" tilecount="48" columns="12">
 <image source="AnimationSheet_OverheadMew.png" width="384" height="192"/>
 <tile id="0">
  <properties>
   <property name="animation" value="idle-front"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="2000"/>
   <frame tileid="2" duration="125"/>
   <frame tileid="4" duration="125"/>
   <frame tileid="2" duration="125"/>
  </animation>
 </tile>
 <tile id="3">
  <properties>
   <property name="animation" value="walk-front"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="6" duration="250"/>
   <frame tileid="0" duration="250"/>
   <frame tileid="8" duration="250"/>
   <frame tileid="0" duration="250"/>
  </animation>
 </tile>
 <tile id="6">
  <properties>
   <property name="animation" value="idle-back"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="12" duration="250"/>
  </animation>
 </tile>
 <tile id="7">
  <properties>
   <property name="animation" value="walk-back"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="14" duration="250"/>
   <frame tileid="16" duration="250"/>
   <frame tileid="12" duration="250"/>
   <frame tileid="18" duration="250"/>
   <frame tileid="20" duration="250"/>
   <frame tileid="18" duration="250"/>
   <frame tileid="12" duration="250"/>
  </animation>
 </tile>
 <tile id="12">
  <properties>
   <property name="animation" value="idle-left"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="24" duration="250"/>
  </animation>
 </tile>
 <tile id="13">
  <properties>
   <property name="animation" value="walk-left"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="26" duration="250"/>
   <frame tileid="28" duration="250"/>
   <frame tileid="30" duration="250"/>
   <frame tileid="28" duration="250"/>
   <frame tileid="26" duration="250"/>
  </animation>
 </tile>
 <tile id="18">
  <properties>
   <property name="animation" value="walk-right"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="36" duration="250"/>
   <frame tileid="38" duration="250"/>
   <frame tileid="40" duration="250"/>
   <frame tileid="42" duration="250"/>
  </animation>
 </tile>
 <tile id="19">
  <properties>
   <property name="animation" value="idle-right"/>
   <property name="loop" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="38" duration="250"/>
  </animation>
 </tile>
</tileset>
