<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.5" tiledversion="1.7.0" name="tileset" tilewidth="32" tileheight="32" tilecount="4" columns="0">
 <grid orientation="orthogonal" width="1" height="1"/>
 <tile id="0" type="tile">
  <properties>
   <property name="float property" type="float" value="2.2"/>
  </properties>
  <image width="32" height="32" source="../../../images/tile_01.png"/>
  <animation>
   <frame tileid="0" duration="100"/>
   <frame tileid="1" duration="100"/>
   <frame tileid="2" duration="100"/>
   <frame tileid="3" duration="100"/>
  </animation>
 </tile>
 <tile id="1" type="tile">
  <properties>
   <property name="string property" value="testing"/>
  </properties>
  <image width="32" height="32" source="../../../images/tile_02.png"/>
  <objectgroup draworder="index">
   <object id="2" x="13.4358" y="13.5305" width="14.4766" height="13.7197"/>
   <object id="3" x="13.8143" y="1.98699" width="14.2874" height="11.0704">
    <ellipse/>
   </object>
  </objectgroup>
 </tile>
 <tile id="2" type="tile">
  <properties>
   <property name="bool property" type="bool" value="true"/>
  </properties>
  <image width="32" height="32" source="../../../images/tile_03.png"/>
 </tile>
 <tile id="3" type="tile">
  <image width="32" height="32" source="../../../images/tile_04.png"/>
 </tile>
</tileset>
