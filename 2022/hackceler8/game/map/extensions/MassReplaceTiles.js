/// <reference types="@mapeditor/tiled-api" />

/* 	Mass Replace Tiles script by eishiya, last updated 4 Dec 2021

	This script adds two actions to the Map menu to mass replace tiles in a map,
	based on another map that provides the old tile -> new tile mappings.
	It is intended to help update old maps when tilesets change in size or have
	their layouts changed, or when you only want to replace some of the tiles
	instead of all of them.
	
	The first action, "Mass Replace Tiles", replaces tiles in the currently
	active map. When run from the menu, it will look for a "remappingMap" File
	property on the map and use that as the source of remappings.
	
	The second action, "Mass Replace Tiles In Open Maps", will run the "Mass
	Replace Tiles" action on all open maps. If the currently open document looks
	like a valid remapping map, you'll be prompted whether you want to use it.
	Answering "Yes" here allows you to use a particular remapping map without
	having to specify it in any of the maps.
	
	All instances of the old tiles will be replaced by the corresponding
	new tiles, both when used on Tile Layers, and when used as Tile Objects.
	
	
	====================== Setting up your remapping map ======================
	Before you can use this script, you will need to create a remapping map,
	which is a regular Tiled map which will tell this script which old tiles
	should be replaced with which new tiles.
	
	The map should have two Tile Layers:
	"old" should contain the tiles you're replacing. The easiest way to make
		this layer is to select everything in your old tileset and stamp it
		onto the layer. Make sure your map is large enough to fit all that.
		Any empty cells on this layer will be ignored.
	"new" should contain the replacement tiles. Each replacement tile should be
		in the same cell as the old tile, but on this layer instead.
		If a cell on this layer is empty, no change will be made to
		the corresponding old tile.
		
	These layers must be top-level layers (not within a group). If multiple
	layers with these names are present, the uppermost of those will be used.
	
		
	====================== Setting up your map to modify ======================
	When your remapping map is ready, you will need to tell this script
	to use it. 
	
	If you use "Mass Replace Tiles In Open Maps", then run that action with
	the remapping map as your active document and you will be prompted whether
	you want to use that map.
	
	Otherwise, you can specify the remapping map to use for each of your maps.
	In the map(s) that you want to replace tiles in, create a custom property
	of type File called "remappingMap" and set it to the remapping map file.
	
	Hint: After setting the "remappingMap" property, if you click its name,
	you can copy the property, and then paste it into any other maps that
	need to use the same remapping.
	
	You can remove the "remappingMap" property after you're done using
	the mass tile replacer.
	
	
	============================= Tips and Notes ==============================
	The mass replacer will not run a remapping map on itself, so don't worry
	about messing it up by accidentally running the mass replacer on it.
	However, it IS possible to mess up a remapping map by applying a different
	remapping map to it, so make sure that if you're using the batch replacer,
	you only have one remapping map open at a time, and that you never have
	a "remappingMap" property on a remapping map.
	
	You can replace tiles within a single tileset, replace tiles from one
	tileset with tiles from another, or any combination thereof.
	
	If you're using this script to aid in the reorganization of a single
	tileset, I recommend making the new version a separate tileset, so you
	can see both old and new tiles correctly in your remapping and can see
	which tiles correspond to which other tiles.
	
	If a tile appears more than once in the "old" layer, the first mapping found
	will be used. This is usually the leftmost and uppermost occurrence, as
	the remapping is searched column-wise from left to right, top to bottom.
	For clarity, avoid repeating tiles in the "old" layer.
	
	This script doesn't remove references to the old tileset, so you may want
	to remove those yourself if you believe your remapping will completely
	remove any tiles from the old tileset. Perhaps eventually I will write
	a script to automatically remove unused tilesets from maps.
	
	If you're looking to replace a few individual tiles in a map or two,
	this script is probably overkill and requires too much set up. For that
	scenario, take a look at the Replace Tile Tool in my scripts repository.
	https://github.com/eishiya/tiled-scripts
*/

let massReplaceTiles = tiled.registerAction("MassReplaceTiles", function(action) {
	let map = tiled.activeAsset;
	
	if(!map || !map.isTileMap) {
		if(!massReplaceTiles.silentMode) tiled.alert("Error: The active asset must be a TileMap to replace tiles in it.");
		return;
	}
	
	//Get the remappings:
	let remapper;
	
	if(massReplaceTiles.remapperMap) {
		remapper = massReplaceTiles.remapperMap;
	} else {
		remapper = map.property("remappingMap");
		if(!remapper) {
			if(!massReplaceTiles.silentMode) tiled.alert("Error: No \"remappingMap\" custom property set on this map. This should be a File property pointing to your map of tile remappings.");
			return;
		} else if(!remapper.url || remapper.url.length < 1) {
			if(!massReplaceTiles.silentMode) tiled.alert("Error: The \"remappingMap\" custom property doesn't have a file set. It should point to your map of tile remappings.");
			return;
		}
		remapper = tiled.open(remapper);
	}
	if(!remapper || !remapper.isTileMap) {
		if(!massReplaceTiles.silentMode) tiled.alert("Error: The \"remappingMap\" does not point to a valid Tiled Map.");
		return;
	}
	
	if(remapper == map) {
		if(!massReplaceTiles.silentMode) tiled.alert("Warning: This map is the remapping map. Mass Replacing tiles on it will produce garbage. Skipping it.");
		return;
	}
	
	let oldTiles = null, newTiles = null;
	for(let li = 0; li < remapper.layerCount; ++li) {
		let layer = remapper.layerAt(li);
		if(layer.name.toLowerCase() == "old" && layer.isTileLayer)
			oldTiles = layer;
		else if(layer.name.toLowerCase() == "new" && layer.isTileLayer)
			newTiles = layer;
	}
	
	if(!oldTiles && !newTiles) {
		if(!massReplaceTiles.silentMode) tiled.alert("Error: The map of tile remappings does not have the required \"old\" and \"new\" layers, or they're not Tile Layers.");
		return;
	} else if(!oldTiles) {
		if(!massReplaceTiles.silentMode) tiled.alert("Error: The map of tile remappings does not have the required \"old\" layer, or it's not a Tile Layer.");
		return;
	} else if(!newTiles) {
		if(!massReplaceTiles.silentMode) tiled.alert("Error: The map of tile remappings does not have the required \"new\" layer, or it's not a Tile Layer.");
		return;
	}
	
	//Figure out the size of the layers, allowing remapper maps to be infinite:
	let remapperEndX = 0, remapperEndY = 0;
	let remapperStartX = 0, remapperStartY = 0;
	
	//Get the bounding box of all the layers to iterate:
	let oldRegion = oldTiles.region().boundingRect;
	let newRegion = newTiles.region().boundingRect;
	remapperStartX = Math.min(oldRegion.x, newRegion.x);
	remapperStartY = Math.min(oldRegion.y, newRegion.y);
	remapperEndX = Math.min(oldRegion.x + oldRegion.width, newRegion.x + newRegion.width);
	remapperEndY = Math.min(oldRegion.y + oldRegion.height, newRegion.y + newRegion.height);
	//This approach eliminates iterating large regions of empty cells, and allows the script to work on infinite maps.
	
	
	function findReplacement(oldTile) {
		if(!oldTile) return null;
		//iterate over oldTiles to find the oldTile, and get the corresponding tile from newTiles.
		let tile;
		for(let x = remapperStartX; x < remapperEndX; ++x) {
			for(let y = remapperStartY; y < remapperEndY; ++y) {
				tile = oldTiles.tileAt(x, y);
				if(tile == oldTile) {
					return newTiles.tileAt(x, y);
				}
			}
		}
	}
	
	//Some functions for remapping a given layer:
	function remapTileLayer(layer) {
		if(!layer || !layer.isTileLayer) return;
		//iterate all the cells within the area used by tiles. This approach allows
		//the replacer to work on infinite maps, and avoids checking large empty areas.
		let bounds = layer.region().boundingRect;
		let endX = bounds.x + bounds.width;
		let endY = bounds.y + bounds.height;
		let tile;
		let layerEdit = layer.edit();
		for(let x = bounds.x; x < endX; ++x) {
			for(let y = bounds.y; y < endY; ++y) {
				tile = findReplacement(layer.tileAt(x, y));
				if(tile) layerEdit.setTile(x, y, tile, layer.flagsAt(x, y));
			}
		}
		layerEdit.apply();
	}
	
	function remapObjectLayer(layer) {
		//iterate all the objects and replace any assigned tiles
		for(let obj = 0; obj < layer.objectCount; ++obj) {
			let mapObj = layer.objectAt(obj);
			let tile = findReplacement(mapObj.tile);
			if(tile) mapObj.tile = tile;
		}
	}
	
	function remapLayer(layer) {
		if(!layer) return;
		if(layer.isTileLayer) {
			remapTileLayer(layer);
		} else if(layer.isObjectLayer) {
			remapObjectLayer(layer);
		} else if(layer.isGroupLayer) {
			//process over its child layers recursively:
			for(let gi = 0; gi < layer.layerCount; ++gi) {
				remapLayer(layer.layerAt(gi));
			}
		}
	}

	map.macro("Mass Replace Tiles", function() {
		//Remap each layer. Layer groups are handled recursively.
		for(let mi = 0; mi < map.layerCount; ++mi) {
			remapLayer(map.layerAt(mi));
		}
		tiled.activeAsset = map;
	});
});
massReplaceTiles.text = "Mass Replace Tiles";
massReplaceTiles.silentMode = false;
massReplaceTiles.remapperMap = null;


let massReplaceBatch = tiled.registerAction("MassReplaceBatch", function(action) {
	massReplaceTiles.remapperMap = null;
	
	remapper = tiled.activeAsset;
	let remapperIsValid = true;
	if(!remapper || !remapper.isTileMap) {
		remapperIsValid = false;
	} else {
		let oldTiles = false, newTiles = false;
		for(let li = 0; li < remapper.layerCount; ++li) {
			let layer = remapper.layerAt(li);
			if(layer.name.toLowerCase() == "old" && layer.isTileLayer)
				oldTiles = true;
			else if(layer.name.toLowerCase() == "new" && layer.isTileLayer)
				newTiles = true;
		}
		if(!oldTiles || !newTiles) {
			remapperIsValid = false;
		}
	}
	if(remapperIsValid)
		remapperIsValid = tiled.confirm("The active map appears to be a valid remapping map. Would you like to use it for this batch?\nIf you select No, the mass replacer will look for a \"remappingMap\" property on each map.");
	if(remapperIsValid) {
		massReplaceTiles.remapperMap = remapper;
	}
	
	massReplaceTiles.silentMode = true;
	
	//Iterate over open maps and apply the "MassReplaceTiles" action to them.
	let assetCount = tiled.openAssets.length, map;
	for(let asset = 0; asset < assetCount; ++asset) {
		map = tiled.openAssets[asset];
		if(map && map.isTileMap) {
			tiled.activeAsset = map;
			tiled.trigger("MassReplaceTiles");
		}
	}
	tiled.activeAsset = remapper; //go back to the asset where we started
	
	//Reset the options to default, so that the single-map replacer runs normally:
	massReplaceTiles.silentMode = false;
	massReplaceTiles.remapperMap = null;
	
});
massReplaceBatch.text = "Mass Replace Tiles In Open Maps";

tiled.extendMenu("Map", [
    { action: "MassReplaceTiles", before: "MapProperties" },
	{ action: "MassReplaceBatch" },
	{separator: true}
]);