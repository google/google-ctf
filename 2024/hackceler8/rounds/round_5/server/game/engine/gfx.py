# Copyright 2024 Google LLC
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

import copy
import enum
import itertools
import logging
import os
import sys
import struct
import weakref

import numpy as np
from array import array
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Tuple, Dict, List, Set, Iterable, Union

import imgui
import moderngl

from game import constants
from moderngl_window.context.base import KeyModifiers
from moderngl_window.integrations.imgui import ModernglWindowRenderer
from numpy.lib.recfunctions import structured_to_unstructured
from pyrr import Vector3, Matrix44

from PIL import Image
import moderngl_window as mglw
import moderngl as mgl

from game.engine.keys import Keys

Color = Tuple[int, int, int, int]
GL410_COMPAT = (sys.platform == "darwin") or os.environ.get('GL410_COMPAT')


@dataclass(frozen=True, slots=True)
class BaseDrawParams:
    x: float
    y: float


@dataclass(frozen=True, slots=True)
class SpriteDrawParams(BaseDrawParams):
    tex: 'TextureReference'
    scale: float = 1
    alpha: int = 255
    flashing: bool = False


class Flags(enum.Enum):
    CIRCLE = 1
    OUTLINE = 1 << 1
    SOFT = 1 << 2


@dataclass(frozen=True, slots=True)
class ShapeDrawParams(BaseDrawParams):
    # x=xl, y=yb
    xr: float
    yt: float
    color: Color
    flags: int = 0
    border_width: float = 0
    above_sprite: bool = False


def circle_outline(x: float, y: float, radius: float, color: Color, border_width: float = 1) -> ShapeDrawParams:
    assert len(color) == 4
    return ShapeDrawParams(x=x - radius, xr=x + radius, y=y - radius, yt=y + radius,
                           flags=Flags.OUTLINE.value | Flags.CIRCLE.value,
                           border_width=border_width,
                           color=color)


def circle_filled(x: float, y: float, radius: float, color: Color, soft: bool = False) -> ShapeDrawParams:
    assert len(color) == 4
    return ShapeDrawParams(x=x - radius, xr=x + radius, y=y - radius, yt=y + radius,
                           flags=Flags.CIRCLE.value | (Flags.SOFT.value if soft else 0),
                           color=color)


def lrtb_rectangle_outline(left: float, right: float, top: float, bottom: float, color: Color,
                           border: float = 1) -> ShapeDrawParams:
    assert len(color) == 4
    return ShapeDrawParams(x=left, xr=right, y=bottom, yt=top, flags=Flags.OUTLINE.value,
                           color=color, border_width=border)


def rectangle_outline(x: float, y: float, w: float, h: float, color: Color, border: float = 1) -> ShapeDrawParams:
    assert len(color) == 4
    return ShapeDrawParams(x=x-w/2, xr=x+w/2, y=y-h/2, yt=y+h/2, color=color, flags=Flags.OUTLINE.value,
                           border_width=border)


def lrtb_rectangle_filled(left: float, right: float, top: float, bottom: float, color: Color) -> ShapeDrawParams:
    assert len(color) == 4
    return ShapeDrawParams(x=left, xr=right, y=bottom, yt=top, color=color)


def rectangle_filled(x: float, y: float, w: float, h: float, color: Color) -> ShapeDrawParams:
    assert len(color) == 4
    return ShapeDrawParams(x=x-w/2, xr=x+w/2, y=y-h/2, yt=y+h/2, color=color)


FONT_SIZES = [120, 60, 40, 30, 20, 18, 15]
FONT_PIXEL: dict[int, int] = {}
GLOBAL_WINDOW: 'Window' = None
TICKRATE = 60


class Window(mglw.WindowConfig):
    if GL410_COMPAT:
        gl_version = (4, 1)
    else:
        gl_version = (4, 5)
    resizable = True

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.wnd.exit_key = None
        global GLOBAL_WINDOW
        assert GLOBAL_WINDOW is None
        GLOBAL_WINDOW = self
        imgui.create_context()
        self.imgui = ModernglWindowRenderer(self.wnd)
        self.imgui_io = imgui.get_io()
        for i in FONT_SIZES:
            FONT_PIXEL[i] = self.imgui_io.fonts.add_font_from_file_ttf("resources/textbox/Pixel.ttf", i)
        self.imgui.refresh_font_texture()
        global DEFAULT_SHAPE_LAYER
        DEFAULT_SHAPE_LAYER = ShapeLayer()
        Keys.update_ui_keys(self.wnd.keys)
        self.tick_accumulator: float = 0
        self.scale: int = 1

    def key_event(self, key: Any, action: Any, modifiers: KeyModifiers):
        if action == self.wnd.keys.ACTION_PRESS:
            self.on_key_press(key, modifiers)
        elif action == self.wnd.keys.ACTION_RELEASE:
            self.on_key_release(key, modifiers)
        else:
            raise Exception("unknown action")
        # forward to gui
        self.imgui.key_event(key, action, modifiers)

    def render(self, time: float, frame_time: float):
        imgui.new_frame()
        # https://gafferongames.com/post/fix_your_timestep/
        self.tick_accumulator += frame_time
        if self.tick_accumulator >= 1.0/TICKRATE:
            while self.tick_accumulator >= 1.0/TICKRATE:
                self.tick_accumulator -= 1.0/TICKRATE
            # We tick at most once per render to avoid skipping renders of ticks.
            self.tick(1.0/TICKRATE)
        self.draw()
        imgui.end_frame()
        imgui.render()
        self.imgui.render(imgui.get_draw_data())
        self.draw_fader()

    def on_update(self, delta_time: float):
        raise NotImplementedError

    def on_render(self, time: float, frame_time: float):
        raise NotImplementedError

    def on_key_press(self, symbol: Any, _modifiers: KeyModifiers):
        raise NotImplementedError

    def on_key_release(self, symbol: Any, _modifiers: KeyModifiers):
        raise NotImplementedError

    def on_resize(self, width: int, height: int):
        raise NotImplementedError

    def resize(self, width: int, height: int):
        # make sure the scale is proportional, so later we can only use one dimension
        x_scale = mglw.window().viewport_width / constants.SCREEN_WIDTH
        y_scale = mglw.window().viewport_height / constants.SCREEN_HEIGHT
        assert abs(x_scale - y_scale) < 0.01, (x_scale, y_scale)
        self.imgui_io.font_global_scale = x_scale
        self.scale = x_scale
        self.imgui.resize(width, height)
        self.on_resize(width, height)

    def mouse_position_event(self, x, y, dx, dy):
        self.imgui.mouse_position_event(x, y, dx, dy)

    def mouse_drag_event(self, x, y, dx, dy):
        self.imgui.mouse_drag_event(x, y, dx, dy)

    def mouse_scroll_event(self, x_offset, y_offset):
        self.imgui.mouse_scroll_event(x_offset, y_offset)

    def mouse_press_event(self, x, y, button):
        self.imgui.mouse_press_event(x, y, button)

    def mouse_release_event(self, x: int, y: int, button: int):
        self.imgui.mouse_release_event(x, y, button)

    def unicode_char_entered(self, char):
        self.imgui.unicode_char_entered(char)


class Camera:
    def __init__(self, w: int, h: int):
        self.ctx = mglw.ctx()
        self.viewport_width = w
        self.viewport_height = h
        self.projection_matrix = Matrix44.orthogonal_projection(0, w, 0, h, -1, 1)
        self.position = Vector3()
        self.view_matrix = None
        self.ubo = self.ctx.buffer(dynamic=True, reserve=4 * 4 * 4)

    def update(self):
        real_pos = self.position / Vector3([
            self.viewport_width / 2,
            self.viewport_height / 2,
            1
        ])
        self.view_matrix = ~Matrix44.from_translation(real_pos)

    def move_to(self, pos):
        self.position.x = pos[0]
        self.position.y = pos[1]
        self.update()

    def use(self):
        self.ubo.bind_to_uniform_block(0)
        self.ubo.write((self.view_matrix * self.projection_matrix).astype("f4"))


def _get_shader_source(name: str):
    path = os.path.join(os.path.dirname(__file__), "shaders", name)
    if GL410_COMPAT:
        if os.path.exists(path + '_compat'):
            path += '_compat'
    with open(path, "r") as f:
        return f.read()


_BASEDIR = Path(__file__).parents[2]
_PATH_CACHE: dict[str, Path] = {}
_IMAGE_CACHE: dict[Path, Image] = {}
_PATH_TO_ATLAS: dict[Path, "TextureAtlas"] = {}


def _resolve_path(p: str) -> Path:
    if p in _PATH_CACHE:
        return _PATH_CACHE[p]
    ret = Path(p)
    if not ret.exists():
        logging.debug("%s not found, trying with basedir", p)
        ret = _BASEDIR / ret
    ret = ret.resolve(strict=True)
    _PATH_CACHE[p] = ret
    return ret


def _get_image(p: Path) -> Image:
    if p in _IMAGE_CACHE:
        return _IMAGE_CACHE[p]
    i = Image.open(p)
    _IMAGE_CACHE[p] = i
    return i


@dataclass(frozen=True, slots=True)
class TextureReference:
    atlas: 'TextureAtlas' = field(hash=False)
    region_id: int

    @property
    def width(self) -> int:
        return self.atlas.ddata[self.region_id]['w']

    @property
    def height(self) -> int:
        return self.atlas.ddata[self.region_id]['h']

    @property
    def id(self) -> int:
        return id(self.atlas)

    # atlases can't be copied
    def __deepcopy__(self, memodict):
        return TextureReference(self.atlas, copy.deepcopy(self.region_id, memodict))


class OversizeImageException(Exception):
    pass


class TextureAtlas:
    @dataclass(frozen=True, slots=True)
    class LoadParams:
        src_file: Path
        x: int
        y: int
        w: int
        h: int
        flip_h: bool
        flip_v: bool
        flip_diag: bool

    DrawData = np.dtype([('w', 'f4'), ('h', 'f4'), ('uv_bl', 'f4', 2), ('uv_tr', 'f4', 2)])

    def __init__(self, size: int = 4096, id_base: int = 1, spacing: int = 2):
        # careful when passing id_base == 0, reserved (not used now though)
        self.next_free_id = id_base
        self.idmap: dict['TextureAtlas.LoadParams', int] = {}
        self.ddata = np.zeros(10, dtype=self.DrawData)
        self.pil_image = Image.new("RGBA", (size, size))
        # only (x,y), assume entire size is there
        self.allocated_imgs: dict[Path, (int, int)] = {}
        self.dirty = True
        self.texture: Optional[mgl.Texture] = None
        self.sampler: Optional[mgl.Sampler] = None
        self.ssbo: Optional[mgl.Buffer] = None
        self.spacing = spacing

    def get_id_for_params(self, p: LoadParams) -> int:
        if p in self.idmap:
            return self.idmap[p]
        self.dirty = True
        i = self.next_free_id
        self.idmap[p] = i
        if self.ddata.size < i+1:
            self.ddata.resize(max(self.ddata.size, i+128))
        self.ddata[i]['w'] = p.w
        self.ddata[i]['h'] = p.h
        self.next_free_id += 1
        return i

    # w,h == None -> use whole image
    def load(self, path: Path, x: int, y: int, w: Optional[int] = None, h: Optional[int] = None, flip_h: bool = False,
             flip_v: bool = False, flip_diag: bool = False, ignore_oversize=False) -> TextureReference:
        i = _get_image(path)
        # Dumb heuristic for "don't take >half"
        if i.width > self.pil_image.width / 2 or i.height > self.pil_image.height / 2:
            if not ignore_oversize:
                raise OversizeImageException(path)
        if w is None:
            w = i.width
        if h is None:
            h = i.height
        params = self.LoadParams(path, x, y, w, h, flip_h, flip_v, flip_diag)
        id_ = self.get_id_for_params(params)
        return TextureReference(weakref.proxy(self), id_)

    def load_images(self):
        imgs: dict[Path, Image] = {}
        for k,idx in self.idmap.items():
            if k.src_file not in imgs:
                i = _get_image(k.src_file)
                imgs[k.src_file] = i.transpose(Image.FLIP_TOP_BOTTOM)
        sizes = sorted(((v.width, v.height, k) for k, v in imgs.items()), reverse=True)

        # worst 2d binpacking routine in history
        # nb: PIL has (0,0) in upper left
        def place(x: int, y: int, w: int, h: int):
            if w < 32 or h < 32:
                return
            if x > 0:
                x += self.spacing
                w -= self.spacing
            if y > 0:
                y += self.spacing
                h -= self.spacing
            for idx in range(len(sizes)):
                if w >= sizes[idx][0] and h >= sizes[idx][1]:
                    break
            else:
                # none fits
                return
            iw, ih, p = sizes[idx]
            del sizes[idx]
            self.pil_image.paste(imgs[p], (x, y))
            self.allocated_imgs[p] = (x, y)
            logging.debug("<%x> Placed %s (%dx%d) at %d,%d [box %dx%d]", id(self), p, iw, ih, x, y, w, h)
            # below
            place(x, y + ih, iw, h - ih)
            # corner
            place(x + iw, y + ih, w - iw, h - ih)
            # side
            place(x + iw, y, w - iw, ih)

        self.pil_image.paste(0, (0, 0, self.pil_image.width, self.pil_image.height))     # clear
        place(0, 0, self.pil_image.width, self.pil_image.height)
        if not len(sizes) == 0:
            self.pil_image.show()
            raise Exception("Failed to pack all images, left: %s" % repr(sizes))
        # self.pil_image.show()
        self.dirty = False

    def maybe_build(self):
        if not self.dirty:
            return
        self.load_images()
        ctx = mglw.ctx()
        if self.texture:
            self.texture.release()
        self.texture = ctx.texture(self.pil_image.size, components=4,
                                   data=self.pil_image.tobytes())
        if self.sampler:
            self.sampler.release()
        self.sampler = ctx.sampler(texture=self.texture)
        #self.sampler.filter = (moderngl.NEAREST, moderngl.NEAREST)
        self.sampler.filter = (moderngl.LINEAR, moderngl.LINEAR)
        if self.ssbo:
            self.ssbo.release()
        element_size = self.DrawData.itemsize
        self.ssbo = ctx.buffer(reserve=element_size * self.next_free_id)
        self.ddata.resize(self.next_free_id)
        for lp, idx in self.idmap.items():
            ai = self.allocated_imgs[lp.src_file]
            dd = self.ddata[idx]
            x = ai[0] + lp.x
            y = ai[1] + lp.y
            uv_bl = [x / self.pil_image.size[0], y / self.pil_image.size[1]]
            # In the fragment shader we shift all uvs half a texel, so subtract 1 texel from the size to correct
            # ref: https://handmade.network/forums/t/7223-pixel-exact_texture_mapping#22318
            uv_tr = [(x + dd['w']-1) / self.pil_image.size[0], (y + dd['h']-1) / self.pil_image.size[1]]
            if lp.flip_diag:
                uv_bl, uv_tr = uv_tr, uv_bl
            if lp.flip_h:
                uv_bl[0], uv_tr[0] = uv_tr[0], uv_bl[0]
            if lp.flip_v:
                uv_bl[1], uv_tr[1] = uv_tr[1], uv_bl[1]
            self.ddata[idx]['uv_tr'] = uv_tr
            self.ddata[idx]['uv_bl'] = uv_bl
        self.ssbo.write(self.ddata)

    def use(self, texid: int = 0, ssboid: int = 2):
        self.maybe_build()
        self.sampler.use(texid)
        self.ssbo.bind_to_storage_buffer(ssboid)


DEFAULT_ATLAS = TextureAtlas()
GUI_ATLAS = TextureAtlas(size=1024)


def load_image(src: str, *args, **kwargs) -> TextureReference:
    path = _resolve_path(src)
    if path in _PATH_TO_ATLAS:
        # ignore fine here, as it already saw this image
        return _PATH_TO_ATLAS[path].load(path, *args, **kwargs, ignore_oversize=True)
    atlas = DEFAULT_ATLAS
    try:
        ret = atlas.load(path, *args, **kwargs)
    except OversizeImageException:
        # make a new one just for this image
        i = _get_image(path)
        #dim_pow2 = 1<<(max(i.width, i.height)-1).bit_length()
        dim128 = (max(i.width, i.height) // 128 + 1) * 128
        atlas = TextureAtlas(size=dim128)
        ret = atlas.load(path, *args, **kwargs, ignore_oversize=True)
        atlas.maybe_build()
    _PATH_TO_ATLAS[path] = atlas
    return ret


class GuiImage:
    def __init__(self, window: Window, ref: TextureReference, w: int, h: int):
        self.window = window
        self.ref = ref
        self.width = w
        self.height = h

    @classmethod
    def load(cls, win: Window, path: str):
        p = _resolve_path(path)
        ref = GUI_ATLAS.load(p, 0, 0, flip_v=True, ignore_oversize=True)
        image = _get_image(p)
        return cls(win, ref, image.width, image.height)

    def draw(self, **kwargs):
        scale = mglw.window().viewport_width / constants.SCREEN_WIDTH
        GUI_ATLAS.maybe_build()
        tex = GUI_ATLAS.texture
        self.window.imgui.register_texture(tex)
        dd = GUI_ATLAS.ddata[self.ref.region_id]
        imgui.image(tex.glo, dd['w']*scale, dd['h']*scale, tuple(dd['uv_bl']), tuple(dd['uv_tr']), **kwargs)


class ShapeLayer:
    def __init__(self):
        ctx = mglw.ctx()
        self.ctx = ctx
        self.point_buffer = ctx.buffer(dynamic=True, reserve=4 * 4 * 4)
        point_buf_desc = (self.point_buffer, "4f", "in_rect")
        self.colors_buffer = ctx.buffer(dynamic=True, reserve=4 * 4)
        colors_buf_desc = (self.colors_buffer, "4f1", "in_color")
        self.borders_buffer = ctx.buffer(dynamic=True, reserve=4 * 4)
        borders_buf_desc = (self.borders_buffer, "1f", "in_borderWidth")
        self.flags_buffer = ctx.buffer(dynamic=True, reserve=4)
        flags_buf_desc = (self.flags_buffer, "i1", "in_flags")
        self.program = ctx.program(vertex_shader=_get_shader_source("shapelayer_v.glsl"),
                                   fragment_shader=_get_shader_source("shapelayer_f.glsl"),
                                   geometry_shader=_get_shader_source("shapelayer_g.glsl"))
        self.program["Projection"].binding = 0
        self.geo = self.ctx.vertex_array(
            self.program,
            [point_buf_desc, colors_buf_desc, borders_buf_desc, flags_buf_desc],
            mode=ctx.POINTS)
        self.shapes: list[ShapeDrawParams] = []

    def clear(self):
        self.shapes = []

    def add(self, x: ShapeDrawParams):
        self.shapes.append(x)

    def _expand_buffers(self):
        size = len(self.shapes)
        size += 32  # make some extra space
        if size * 4*4 > self.point_buffer.size:
            self.point_buffer.orphan(4 * 4 * size)
            self.colors_buffer.orphan(4 * size)
            self.borders_buffer.orphan(4 * size)
            self.flags_buffer.orphan(size)

    def build(self):
        self._expand_buffers()
        def _point_gen():
            for i in self.shapes:
                yield i.x
                yield i.y
                yield i.xr
                yield i.yt
        self.point_buffer.write(array("f", _point_gen()))
        self.colors_buffer.write(array("B", itertools.chain.from_iterable(i.color for i in self.shapes)))
        self.borders_buffer.write(array("f", (i.border_width for i in self.shapes)))
        self.flags_buffer.write(array("B", (i.flags for i in self.shapes)))

    def draw(self):
        self.build()
        self.ctx.enable_only(self.ctx.BLEND | self.ctx.PROGRAM_POINT_SIZE)
        self.geo.render(mode=self.ctx.POINTS, vertices=len(self.shapes))
        self.clear()


class SpriteLayer:
    def __init__(self):
        ctx = mglw.ctx()
        self.ctx = ctx
        self.point_buffer = ctx.buffer(dynamic=True, reserve=4 * 2 * 4)
        point_buf_desc = (self.point_buffer, "2f", "in_pos")
        self.alphas_buffer = ctx.buffer(dynamic=True, reserve=1 * 4)
        alphas_buf_desc = (self.alphas_buffer, "1f1", "in_alpha")
        self.scales_buffer = ctx.buffer(dynamic=True, reserve=4 * 4)
        scales_buf_desc = (self.scales_buffer, "1f", "in_scale")
        self.flashing_buffer = ctx.buffer(dynamic=True, reserve=4)
        flashing_buf_desc = (self.flashing_buffer, "1i1", "in_flashing")
        self.program = ctx.program(vertex_shader=_get_shader_source("spritelayer_base_v.glsl"),
                                   fragment_shader=_get_shader_source("spritelayer_base_f.glsl"),
                                   geometry_shader=_get_shader_source("spritelayer_base_g.glsl"))
        # we can't use layout binding qualifiers because of OSX, so force them here
        self.program["tex"] = 0
        self.program["Projection"].binding = 0
        descriptors = [point_buf_desc, alphas_buf_desc, scales_buf_desc, flashing_buf_desc]
        if GL410_COMPAT:
            self.size_buffer = ctx.buffer(dynamic=True, reserve=4 * 2 * 4)
            descriptors.append((self.size_buffer, "2f", "in_size"))
            self.uv_bl_buffer = ctx.buffer(dynamic=True, reserve=4 * 2 * 4)
            descriptors.append((self.uv_bl_buffer, "2f", "in_uvBL"))
            self.uv_tr_buffer = ctx.buffer(dynamic=True, reserve=4 * 2 * 4)
            descriptors.append((self.uv_tr_buffer , "2f", "in_uvTR"))
        else:
            self.txs_buffer = ctx.buffer(dynamic=True, reserve=4 * 4)
            descriptors.append((self.txs_buffer, "1i", "in_idx"))
        self.geo = self.ctx.vertex_array(self.program, descriptors, mode=ctx.POINTS)
        self.draws_per_tex: defaultdict[int, List[SpriteDrawParams]] = defaultdict(list)

    def update_list(self, infos: Iterable[SpriteDrawParams]):
        self.draws_per_tex.clear()
        for i in infos:
            # allow passing nones here for convenience
            if i is None:
                continue
            self.add(i)

    def add(self, i: SpriteDrawParams):
        assert isinstance(i, SpriteDrawParams), i
        assert i.tex is not None
        self.draws_per_tex[i.tex.id].append(i)

    def clear(self):
        self.draws_per_tex.clear()

    def _expand_buffers(self, size: int):
        size += 32  # make some extra space
        if size * 2 * 4 > self.point_buffer.size:
            self.point_buffer.orphan(4 * 2 * size)
            self.alphas_buffer.orphan(1 * size)
            self.scales_buffer.orphan(4 * size)
            self.flashing_buffer.orphan(1 * size)
            if GL410_COMPAT:
                self.size_buffer.orphan(4 * 2 * size)
                self.uv_bl_buffer.orphan(4 * 2 * size)
                self.uv_tr_buffer.orphan(4 * 2 * size)
            else:
                self.txs_buffer.orphan(4 * size)

    def _update_buffer_for_texid(self, texid: int):
        infos = self.draws_per_tex[texid]
        count = len(infos)
        if count * 2 * 4 > self.point_buffer.size:
            self._expand_buffers(count)

        def _point_gen():
            for i in infos:
                yield i.x
                yield i.y

        def _idxs_gen():
            for i in infos:
                yield i.tex.region_id

        def _scales_gen():
            for i in infos:
                yield i.scale

        self.point_buffer.write(array("f", _point_gen()))
        self.scales_buffer.write(array("f", _scales_gen()))
        self.alphas_buffer.write(array("B", (i.alpha for i in infos)))
        self.flashing_buffer.write(array("B", (1 if i.flashing else 0 for i in infos)))
        if GL410_COMPAT:
            # hack, we know the atlas is the same for all infos
            infos[0].tex.atlas.maybe_build()
            for offset, info in enumerate(infos):
                dd = info.tex.atlas.ddata[info.tex.region_id]
                self.size_buffer.write(structured_to_unstructured(dd[['w', 'h']]).view('f4'), offset=offset*2*4)
                self.uv_tr_buffer.write(dd['uv_tr'].view('f4'), offset=offset*2*4)
                self.uv_bl_buffer.write(dd['uv_bl'].view('f4'), offset=offset*2*4)
        else:
            self.txs_buffer.write(array("i", _idxs_gen()))

    def draw_all(self):
        self.update_all_buffers()
        self.draw_all_cached()

    def update_all_buffers(self):
        for texid in self.draws_per_tex:
            self._update_buffer_for_texid(texid)

    def draw_all_cached(self):
        for texid, infos in self.draws_per_tex.items():
            count = len(infos)
            infos[0].tex.atlas.use(0)
            self.ctx.enable_only(self.ctx.BLEND | self.ctx.PROGRAM_POINT_SIZE)
            self.geo.render(mode=self.ctx.POINTS, vertices=count)


IterableParams = Union[Iterable[BaseDrawParams], Iterable["IterableParams"]]


class CombinedLayer:
    def __init__(self):
        self.shape = ShapeLayer()
        self.sprite = SpriteLayer()
        self.shape_above_sprite = ShapeLayer()

    def add(self, x: BaseDrawParams):
        if isinstance(x, SpriteDrawParams):
            self.sprite.add(x)
        elif isinstance(x, ShapeDrawParams):
            if x.above_sprite:
                self.shape_above_sprite.add(x)
            else:
                self.shape.add(x)
        else:
            raise TypeError("Unsupported class %s" % str(x))

    def add_many(self, xs: IterableParams):
        for i in xs:
            if isinstance(i, BaseDrawParams):
                self.add(i)
            else:
                self.add_many(i)

    def clear(self):
        self.shape.clear()
        self.sprite.clear()
        self.shape_above_sprite.clear()

    def draw(self):
        self.shape.draw()
        self.sprite.draw_all()
        self.shape_above_sprite.draw()


class TileMap:
    def __init__(self):
        self.layer_infos: defaultdict[str, list[SpriteDrawParams]] = defaultdict(list)
        self.layers: dict[str, SpriteLayer] = {}
        self.ctx = None

    def add_sprite(self, layer: str, img, x: int, y: int):
        self.layer_infos[layer].append(SpriteDrawParams(x=x, y=y, scale=1, alpha=255, tex=img))

    def build(self):
        for layer_name, infos in self.layer_infos.items():
            layer = SpriteLayer()
            assert len(infos) == len(set(infos))
            layer.update_list(infos)
            layer.update_all_buffers()
            self.layers[layer_name] = layer

    def draw(self):
        for layer in self.layers.values():
            if GL410_COMPAT:
                # If the texture atlas was rebuilt since this Tilemap.build(), the uvs in compat spritelayer uv buffers
                # no longer match the texture, so we need to regenerate the whole VAO. This is not an issue on gl450,
                # as the atlas will update the SSBO directly.
                layer.update_all_buffers()
            layer.draw_all_cached()


def _clamp_viewport_x(x: int):
    x *= GLOBAL_WINDOW.scale
    if x < 0:
        x = mglw.window().viewport_width + x
    return x


def _clamp_viewport_y(y: int):
    y *= GLOBAL_WINDOW.scale
    if y < 0:
        y = mglw.window().viewport_height + y
    return y


# Negative x/y values mean distance from the right/bottom
def draw_img(name: str, img: GuiImage, x: int, y: int):
    x = _clamp_viewport_x(x)
    y = _clamp_viewport_y(y)
    imgui.set_next_window_position(x, y)
    imgui.set_next_window_size(0, 0)
    with imgui.begin(name+"_img",
                     flags=imgui.WINDOW_NO_DECORATION|imgui.WINDOW_NO_NAV|imgui.WINDOW_NO_BACKGROUND):
        img.draw()


def draw_txt(name, font, txt, x, y, color=None):
    x = _clamp_viewport_x(x)
    y = _clamp_viewport_y(y)
    imgui.set_next_window_position(x, y)
    imgui.set_next_window_size(0, 0)
    with imgui.begin(name+"_txt",
                     flags=imgui.WINDOW_NO_DECORATION|imgui.WINDOW_NO_NAV|imgui.WINDOW_NO_BACKGROUND):
        with imgui.font(font):
            if color is None:
                imgui.text(txt)
            else:
                imgui.text_colored(txt, color[0], color[1], color[2], color[3] if len(color) == 4 else 1)
