/// <reference types="@mapeditor/tiled-api" />

let action = tiled.registerAction("SelectTile", action => {
    tiled.log(selectedTiles);

    if (!tiled.activeAsset.isTileMap) {
        return;
    }
    var map = tiled.activeAsset as TileMap;
    for(const layer of map.selectedLayers) {
        tiled.log(layer.name)
        if (!layer.isObjectLayer) {
            continue;
        }
        const l = layer as ObjectGroup;
        var selectedTiles = tiled.mapEditor.tilesetsView.selectedTiles;
        for (const obj of l.objects) {
            var found = false;
            for (const selTile of selectedTiles) {
                if (obj.tile === selTile) {
                    found = true;
                }
            }
            obj.selected = found;
        }
    }
    
})

action.text = "Select All Objects"

tiled.extendMenu("TilesetView.Tiles", [
    {action: "SelectTile"}
])

