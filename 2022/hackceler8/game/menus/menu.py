# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from arcade import gui
from typing import Iterable, Optional
from pyglet.event import EventDispatcher

class BorderedMenu(gui.UIBoxLayout):
    """A widget that surrounds another widget in an aesthetic box."""
    def __init__(self, game, child: Optional[gui.widgets.UIWidget] = None, tileset=None, tileset_start=0, x: float = 0, y: float = 0, **kwargs):
        super().__init__(x=x, y=y, vertical=False, align='center', children=(), **kwargs)

        tileset = tileset or game.find_tileset("window-border")

        topleft = game.make_texture(tileset.tiles[tileset_start])
        top = game.make_texture(tileset.tiles[tileset_start + 1])
        topright = game.make_texture(tileset.tiles[tileset_start + 2])
        left = game.make_texture(tileset.tiles[tileset_start + 3])
        center = game.make_texture(tileset.tiles[tileset_start + 4])
        right = game.make_texture(tileset.tiles[tileset_start + 5])
        bottomleft = game.make_texture(tileset.tiles[tileset_start + 6])
        bottom = game.make_texture(tileset.tiles[tileset_start + 7])
        bottomright = game.make_texture(tileset.tiles[tileset_start + 8])

        self._bgwrapper = gui.UITexturePane(child=child or gui.UIWidget(width=32, height=32, tex=center),
                                            tex=center)
        self.child = self._bgwrapper.child

        leftcol = gui.UIBoxLayout(align="left")
        leftcol.add(gui.UITexturePane(child=gui.UIWidget(width=32, height=32), tex=topleft))
        self.left_widget = gui.UIWidget(width=32, height=self._bgwrapper.height)
        leftcol.add(gui.UITexturePane(child=self.left_widget, tex=left))
        leftcol.add(gui.UITexturePane(child=gui.UIWidget(width=32, height=32), tex=bottomleft))

        centercol = gui.UIBoxLayout(align="center")
        self.top_widget = gui.UIWidget(width=self._bgwrapper.width, height=32)
        centercol.add(gui.UITexturePane(child=self.top_widget, tex=top))

        centercol.add(self._bgwrapper)

        self.bottom_widget = gui.UIWidget(width=self._bgwrapper.width, height=32)
        centercol.add(gui.UITexturePane(child=self.bottom_widget, tex=bottom))

        rightcol = gui.UIBoxLayout(align="right")
        rightcol.add(gui.UITexturePane(child=gui.UIWidget(width=32, height=32), tex=topright))
        self.right_widget = gui.UIWidget(width=32, height=self._bgwrapper.height)
        rightcol.add(gui.UITexturePane(child=self.right_widget, tex=right))
        rightcol.add(gui.UITexturePane(child=gui.UIWidget(width=32, height=32), tex=bottomright))

        self.add(leftcol)
        self.add(centercol)
        self.add(rightcol)


    @property
    def child(self):
        return self._bgwrapper.child

    @child.setter
    def child(self, value):
        self._bgwrapper.child = value

    def do_layout(self):
        if self._bgwrapper.height != self.left_widget.height:
            self.left_widget.rect = self.left_widget.rect.resize(height=self._bgwrapper.height)
            self.right_widget.rect = self.right_widget.rect.resize(height=self._bgwrapper.height)
        if self._bgwrapper.width != self.top_widget.width:
            self.top_widget.rect = self.top_widget.rect.resize(width=self._bgwrapper.width)
            self.bottom_widget.rect = self.bottom_widget.rect.resize(width=self._bgwrapper.width)
        super().do_layout()

class TextBox(gui.UIInputText):
    """A text entry box with a white background that offers an on_submit event (enter pressed)."""
    def __init__(self,
                 game,
                 x: float = 0,
                 y: float = 0,
                 width: float = 100,
                 height: float = 50,
                 text: str = "",
                 font_name=('Arial',),
                 font_size: float = 12,
                 text_color = (0, 0, 0, 255),
                 multiline=False,
                 size_hint=None,
                 size_hint_min=None,
                 size_hint_max=None,
                 style=None,
                 **kwargs):
        super().__init__(x=x, y=y, width=width, height=height, text=text, font_name=font_name, font_size=font_size,
                         text_color=text_color, multiline=multiline, size_hint=None, size_hint_min=None,
                         size_hint_max=None, style=None, **kwargs)

        self._active = True
        self._old_insert_text = self.doc.insert_text
        self.doc.insert_text = self._insert_text
        self._tex = game.make_texture(game.find_tileset("white_square").tiles[0])

    def _insert_text(self, start, text: str, attributes=None):
        submit = False
        if '\n' in text:
            submit = True
            text = text.replace("\n", "")

        if text:
            self._old_insert_text(start, text, attributes)
        if submit:
            self.dispatch_event("on_submit", self.text)

    def do_render(self, surface):
        self.prepare_render(surface)
        surface.draw_texture(0, 0, self.width, self.height, tex=self._tex)
        super().do_render(surface)


TextBox.register_event_type("on_submit")

def spinner(game, background=True, *args, **kwargs):
    if background:
        name = "spinner_bg"
    else:
        name = "spinner"
    return gui.UISpriteWidget(sprite = game.make_sprite(game.find_frameset(name)), *args, **kwargs)

def wrap_menu_background(game, child, tileset=None, tileset_start=0):
    tileset = tileset or game.find_tileset("window-border")
    center = game.make_texture(tileset.tiles[tileset_start + 4])
    return gui.UITexturePane(child=child, tex=center, width=child.width, height=child.height)
