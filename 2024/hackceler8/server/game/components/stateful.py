import logging

from game.engine import generics


class StatefulObject(generics.GenericObject):
    def draw(self):
        self.draw()

    def __init__(self, coords, tileset_path, name, ):
        super().__init__(
            coords,
            nametype="Stateful",
            tileset_path=tileset_path,
            name=name,
            can_flip=True,
        )

    def tick(self):
        super().tick()


class Crops(StatefulObject):
    def __init__(self, coords):
        super().__init__(
            coords=coords,
            tileset_path="resources/objects/fire.h8t",
            name="crops"
        )
        self.size = 0

    def tick(self):
        super().tick()
        self.size += 0.1
        if self.size == 10:
            logging.info(self.size)


