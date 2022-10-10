// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

const FRAMES = 6000;
const CHARSET = {'A': [14, 17, 31, 17, 17, 17, 17], 'B': [30, 17, 30, 17, 17, 17, 30], 'C': [14, 17, 16, 16, 16, 17, 14], 'D': [30, 17, 17, 17, 17, 17, 30], 'E': [31, 16, 31, 16, 16, 16, 31], 'F': [31, 16, 31, 16, 16, 16, 16], 'G': [15, 16, 19, 17, 17, 17, 14], 'H': [17, 17, 31, 17, 17, 17, 17], 'I': [14, 4, 4, 4, 4, 4, 14], 'J': [1, 1, 1, 1, 1, 17, 14], 'K': [17, 18, 28, 18, 17, 17, 17], 'L': [16, 16, 16, 16, 16, 16, 31], 'M': [17, 27, 21, 17, 17, 17, 17], 'N': [17, 25, 21, 19, 17, 17, 17], 'O': [14, 17, 17, 17, 17, 17, 14], 'P': [30, 17, 30, 16, 16, 16, 16], 'Q': [14, 17, 17, 17, 17, 18, 13], 'R': [30, 17, 30, 17, 17, 17, 17], 'S': [14, 16, 14, 1, 1, 17, 14], 'T': [31, 4, 4, 4, 4, 4, 4], 'U': [17, 17, 17, 17, 17, 17, 14], 'V': [17, 17, 17, 17, 10, 10, 4], 'W': [17, 17, 17, 17, 21, 27, 17], 'X': [17, 17, 10, 4, 10, 17, 17], 'Y': [17, 10, 4, 4, 4, 4, 4], 'Z': [31, 1, 2, 4, 8, 16, 31], 'a': [0, 0, 14, 1, 15, 17, 15], 'b': [16, 16, 22, 25, 17, 17, 30], 'c': [0, 0, 14, 17, 16, 17, 14], 'd': [1, 1, 13, 19, 17, 17, 15], 'e': [0, 0, 14, 17, 31, 16, 15], 'f': [3, 4, 15, 4, 4, 4, 4], 'g': [0, 15, 17, 17, 15, 1, 30], 'h': [16, 16, 22, 25, 17, 17, 17], 'i': [0, 4, 0, 4, 4, 4, 4], 'j': [2, 0, 2, 2, 18, 18, 12], 'k': [8, 8, 9, 10, 12, 10, 9], 'l': [8, 8, 8, 8, 8, 8, 4], 'm': [0, 0, 26, 21, 21, 17, 17], 'n': [0, 0, 30, 17, 17, 17, 17], 'o': [0, 0, 14, 17, 17, 17, 14], 'p': [0, 22, 25, 17, 30, 16, 16], 'q': [0, 13, 19, 17, 15, 1, 1], 'r': [0, 0, 22, 25, 16, 16, 16], 's': [0, 0, 15, 16, 14, 1, 30], 't': [0, 4, 14, 4, 4, 4, 2], 'u': [0, 0, 17, 17, 17, 17, 15], 'v': [0, 0, 17, 17, 17, 10, 4], 'w': [0, 0, 17, 17, 21, 21, 15], 'x': [0, 0, 17, 10, 4, 10, 17], 'y': [0, 17, 17, 17, 15, 1, 30], 'z': [0, 0, 31, 2, 4, 8, 31], '0': [14, 17, 19, 21, 25, 17, 14], '1': [4, 12, 4, 4, 4, 4, 31], '2': [14, 17, 1, 6, 8, 16, 31], '3': [14, 17, 1, 6, 1, 17, 14], '4': [3, 5, 9, 17, 31, 1, 1], '5': [31, 16, 30, 1, 1, 17, 14], '6': [6, 8, 16, 30, 17, 17, 14], '7': [31, 17, 1, 2, 4, 4, 4], '8': [14, 17, 17, 14, 17, 17, 14], '9': [14, 17, 17, 15, 1, 2, 12], '_': [0, 0, 0, 0, 0, 0, 31], '.': [0, 0, 0, 0, 0, 0, 4], '{': [6, 8, 8, 16, 8, 8, 6], '}': [12, 2, 2, 1, 2, 2, 12], '?': [14, 17, 1, 2, 4, 0, 4], '!': [4, 4, 4, 4, 4, 0, 4]};

const COPY = `#version 300 es
#ifdef GL_ES
precision highp float;
precision highp int;
#endif
uniform sampler2D state;
uniform vec2 scale;
out vec4 fragColor;
void main(){fragColor=texture(state,gl_FragCoord.xy/scale);}
`;
const QUAD = `#version 300 es
#ifdef GL_ES
precision highp float;
precision highp int;
#endif
in vec2 quad;
void main(){gl_Position=vec4(quad,0,1.0);}
`;

const CA = `#version 300 es
#ifdef GL_ES
precision highp float;
precision highp int;
#endif

uniform sampler2D state;
uniform vec2 scale;
uniform int f;
out vec4 fragColor;

ivec4 r(vec2 off) {
  vec4 p = texture(state, (gl_FragCoord.xy + off) / scale) * 255.0;
  return ivec4(
    (int(p.r) & 0xf0) >> 4,
    (int(p.g) & 0xf0) >> 4,
    (int(p.b) & 0xf0) >> 4,
    (int(p.r) & 0xc) | ((int(p.g) & 0xc) >> 2));
}
vec4 ww(ivec4 b) {
  return vec4(
    float((b.r << 4) | (b.a & 0xc)) / 255.0,
    float((b.g << 4) | ((b.a << 2) & 0xc)) / 255.0,
    float(b.b << 4) / 255.0,
    1.0);
}
ivec4 pb(ivec4 b) {
  int n = (b.r << 12) | (b.g << 8) | (b.b << 4) | b.a;
  if (n < 62057) {
    n = (n * (f + 7) * 11) % 62057;
  }
  return ivec4(
    (n & 0xf000) >> 12,
    (n & 0xf00) >> 8,
    (n & 0xf0) >> 4,
    (n & 0xf));
}
void main() {
  ivec4 o = r(vec2(0.0));
  ivec4 n = r(vec2(0.0, -1.0));
  ivec4 ne = r(vec2(1.0, -1.0));
  ivec4 e = r(vec2(1.0, 0.0));
  ivec4 se = r(vec2(1.0, 1.0));
  ivec4 s = r(vec2(0.0, 1.0));
  ivec4 sw = r(vec2(-1.0, 1.0));
  ivec4 w = r(vec2(-1.0, 0.0));
  ivec4 nw = r(vec2(-1.0, -1.0));
  if (f % 4 == 0) {
    o = pb(o);
  } else if (f % 4 == 1) {
    ivec4 tl = ivec4(0);
    tl.r = ((nw.g << 1) & 0xe) | (n.g >> 3);
    tl.g = ((nw.b << 1) & 0xe) | (n.b >> 3);
    tl.b = ((nw.a << 1) & 0xe) | (n.a >> 3);
    tl.a = ((w.r << 1) & 0xe) | (o.r >> 3);
    tl = pb(tl);
    ivec4 tr = ivec4(0);
    tr.r = ((n.g << 1) & 0xe) | (ne.g >> 3);
    tr.g = ((n.b << 1) & 0xe) | (ne.b >> 3);
    tr.b = ((n.a << 1) & 0xe) | (ne.a >> 3);
    tr.a = ((o.r << 1) & 0xe) | (e.r >> 3);
    tr = pb(tr);
    ivec4 bl = ivec4(0);
    bl.r = ((w.g << 1) & 0xe) | (o.g >> 3);
    bl.g = ((w.b << 1) & 0xe) | (o.b >> 3);
    bl.b = ((w.a << 1) & 0xe) | (o.a >> 3);
    bl.a = ((sw.r << 1) & 0xe) | (s.r >> 3);
    bl = pb(bl);
    ivec4 br = ivec4(0);
    br.r = ((o.g << 1) & 0xe) | (e.g >> 3);
    br.g = ((o.b << 1) & 0xe) | (e.b >> 3);
    br.b = ((o.a << 1) & 0xe) | (e.a >> 3);
    br.a = ((s.r << 1) & 0xe) | (se.r >> 3);
    br = pb(br);
    o.r = ((tl.a << 3) & 0x8) | (tr.a >> 1);
    o.g = ((bl.r << 3) & 0x8) | (br.r >> 1);
    o.b = ((bl.g << 3) & 0x8) | (br.g >> 1);
    o.a = ((bl.b << 3) & 0x8) | (br.b >> 1);
  } else if (f % 4 == 2) {
    ivec4 tl = ivec4(0);
    tl.r = ((nw.b << 2) & 0xc) | (n.b >> 2) ;
    tl.g = ((nw.a << 2) & 0xc) | (n.a >> 2);
    tl.b = ((w.r << 2) & 0xc) | (o.r >> 2);
    tl.a = ((w.g << 2) & 0xc) | (o.g >> 2);
    tl = pb(tl);
    ivec4 tr = ivec4(0);
    tr.r = ((n.b << 2) & 0xc) | (ne.b >> 2);
    tr.g = ((n.a << 2) & 0xc) | (ne.a >> 2);
    tr.b = ((o.r << 2) & 0xc) | (e.r >> 2);
    tr.a = ((o.g << 2) & 0xc) | (e.g >> 2);
    tr = pb(tr);
    ivec4 bl = ivec4(0);
    bl.r = ((w.b << 2) & 0xc) | (o.b >> 2);
    bl.g = ((w.a << 2) & 0xc) | (o.a >> 2);
    bl.b = ((sw.r << 2) & 0xc) | (s.r >> 2);
    bl.a = ((sw.g << 2) & 0xc) | (s.g >> 2);
    bl = pb(bl);
    ivec4 br = ivec4(0);
    br.r = ((o.b << 2) & 0xc) | (e.b >> 2);
    br.g = ((o.a << 2) & 0xc) | (e.a >> 2);
    br.b = ((s.r << 2) & 0xc) | (se.r >> 2);
    br.a = ((s.g << 2) & 0xc) | (se.g >> 2);
    br = pb(br);
    o.r = ((tl.b << 2) & 0xc) | (tr.b >> 2);
    o.g = ((tl.a << 2) & 0xc) | (tr.a >> 2);
    o.b = ((bl.r << 2) & 0xc) | (br.r >> 2);
    o.a = ((bl.g << 2) & 0xc) | (br.g >> 2);
  } else {
    ivec4 tl = ivec4(0);
    tl.r = ((nw.a << 3) & 0x8) | (n.a >> 1);
    tl.g = ((w.r << 3) & 0x8) | (o.r >> 1);
    tl.b = ((w.g << 3) & 0x8) | (o.g >> 1);
    tl.a = ((w.b << 3) & 0x8) | (o.b >> 1);
    tl = pb(tl);
    ivec4 tr = ivec4(0);
    tr.r = ((n.a << 3) & 0x8) | (ne.a >> 1);
    tr.g = ((o.r << 3) & 0x8) | (e.r >> 1);
    tr.b = ((o.g << 3) & 0x8) | (e.g >> 1);
    tr.a = ((o.b << 3) & 0x8) | (e.b >> 1);
    tr = pb(tr);
    ivec4 bl = ivec4(0);
    bl.r = ((w.a << 3) & 0x8) | (o.a >> 1);
    bl.g = ((sw.r << 3) & 0x8) | (s.r >> 1);
    bl.b = ((sw.g << 3) & 0x8) | (s.g >> 1);
    bl.a = ((sw.b << 3) & 0x8) | (s.b >> 1);
    bl = pb(bl);
    ivec4 br = ivec4(0);
    br.r = ((o.a << 3) & 0x8) | (e.a >> 1);
    br.g = ((s.r << 3) & 0x8) | (se.r >> 1);
    br.b = ((s.g << 3) & 0x8) | (se.g >> 1);
    br.a = ((s.b << 3) & 0x8) | (se.b >> 1);
    br = pb(br);
    o.r = ((tl.g << 1) & 0xe) | (tr.g >> 3);
    o.g = ((tl.b << 1) & 0xe) | (tr.b >> 3);
    o.b = ((tl.a << 1) & 0xe) | (tr.a >> 3);
    o.a = ((bl.r << 1) & 0xe) | (br.r >> 3);
  }
  fragColor = ww(o);
}`;

let gl = null;
const QUAD2 = new Float32Array([-1, -1, 1, -1, -1, 1, 1, 1]);

const isArray = (object) => {
    var name = Object.prototype.toString.apply(object, []),
        re = / (Float(32|64)|Int(16|32|8)|Uint(16|32|8(Clamped)?))?Array]$/;
    return re.exec(name) != null;
};

const getContext = (canvas) => {
    try {
        const gl = canvas.getContext('webgl2');
        gl.pixelStorei(gl.UNPACK_FLIP_Y_WEBGL, true);
        return gl;
    } catch (e) {
        throw new Error('Could not create WebGL context.');
    }
};

class Program {
    constructor(vertex, fragment) {
        this.program = gl.createProgram();
        this.vars = {};
        gl.attachShader(this.program,
            this.makeShader(gl.VERTEX_SHADER, vertex));
        gl.attachShader(this.program,
            this.makeShader(gl.FRAGMENT_SHADER, fragment));
        gl.linkProgram(this.program);
        if (!gl.getProgramParameter(this.program, gl.LINK_STATUS)) {
            throw new Error(gl.getProgramInfoLog(this.program));
        }
    }
    makeShader(type, source) {
        const shader = gl.createShader(type);
        gl.shaderSource(shader, source);
        gl.compileShader(shader);
        if (gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
            return shader;
        } else {
            throw new Error(gl.getShaderInfoLog(shader));
        }
    }
    use() {
        gl.useProgram(this.program);
        return this;
    }
    uniform(name, value, i=false) {
        if (!(name in this.vars)) {
            this.vars[name] = gl.getUniformLocation(this.program, name);
        }
        const v = this.vars[name];
        if (isArray(value)) {
            var method = 'uniform' + value.length + (i ? 'i' : 'f') + 'v';
            gl[method](v, value);
        } else if (typeof value === 'number' || typeof value === 'boolean') {
            if (i) {
                gl.uniform1i(v, value);
            } else {
                gl.uniform1f(v, value);
            }
        } else {
            throw new Error('Invalid uniform value: ' + value);
        }
        return this;
    }
    uniformi(name, value) {
        return this.uniform(name, value, true);
    }
    attrib(name, value, size) {
        if (!(name in this.vars)) {
            this.vars[name] = gl.getAttribLocation(this.program, name);
        }
        value.bind();
        gl.enableVertexAttribArray(this.vars[name]);
        gl.vertexAttribPointer(this.vars[name], size, gl.FLOAT,
                               false, 0, 0);
        return this;
    }
    draw() {
        gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
    }
}

class Buffer {
    constructor() {
        this.buffer = gl.createBuffer();
        this.target = gl.ARRAY_BUFFER;
        return this;
    }
    bind() {
        gl.bindBuffer(this.target, this.buffer);
    }
    update(data) {
        this.bind();
        gl.bufferData(this.target, data, gl.STATIC_DRAW);
        return this;
    }
}

class Texture {
    constructor() {
        this.texture = gl.createTexture();
        this.format = gl.RGBA;
        this.type = gl.UNSIGNED_BYTE;
        gl.bindTexture(gl.TEXTURE_2D, this.texture);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.REPEAT);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.REPEAT);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.NEAREST);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.NEAREST);
        return this;
    }
    bind(u) {
        if (u != null) {
            gl.activeTexture(gl.TEXTURE0 + u);
        }
        gl.bindTexture(gl.TEXTURE_2D, this.texture);
    }
    blank(w, h) {
        this.bind();
        gl.texImage2D(gl.TEXTURE_2D, 0, this.format, w, h,
                      0, this.format, this.type, null);
        return this;
    }
    set(source, w, h) {
        this.bind();
        source = new Uint8Array(source);
        gl.texSubImage2D(gl.TEXTURE_2D, 0, 0, 0,
            w, h, this.format, this.type, source);
    }
}

class Framebuffer {
    constructor(buffer=gl.createFramebuffer()) {
        this.buffer = buffer;
    }
    bind() {
        gl.bindFramebuffer(gl.FRAMEBUFFER, this.buffer);
    }
    attach(texture) {
        this.bind();
        gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0,
                                gl.TEXTURE_2D, texture.texture, 0);
    }
}

class BCA {
    constructor(canvas) {
      gl = getContext(canvas);
      if (gl == null) {
        alert('Could not initialize WebGL!');
        throw new Error('No WebGL');
      }
      const w = 1024, h = 1024;
      this.canvas = canvas;
      this.size = new Float32Array([w, h]);
      gl.disable(gl.DEPTH_TEST);
      this.programs = {
        copy: new Program(QUAD, COPY),
        cellular: new Program(QUAD, CA),
      };
      this.buffers = {
        quad: new Buffer().update(QUAD2)
      };
      this.textures = {
        front: new Texture().blank(w, h),
        back: new Texture().blank(w, h)
      };
      this.framebuffers = {
        step: new Framebuffer(),
        default: new Framebuffer(null),
      };
      this.t = 0;
    }
    set(state) {
      const rgba = new Uint8Array(this.size[0] * this.size[1] * 4);
      for (let i = 0; i < state.length; ++i) {
        let ii = i * 4;
        rgba[ii] = state[i] & 0xff;
        rgba[ii + 1] = (state[i] & 0xffff) >> 8;
        rgba[ii + 2] = (state[i] & 0xffffff) >> 16;
        rgba[ii + 3] = 255;
      }
      this.textures.front.set(rgba, this.size[0], this.size[1]);
      return this;
    }
    setState(f) {
      const size = this.size[0] * this.size[1];
      const buf = new Uint32Array(size);
      for (let i = 0; i < size; i++) {
        buf[i] = 0;
      }
      for (let dy = 0; dy < 16; ++dy) {
        let px = 64 + 32 * dy;
        for (let p = 0; p < f.length; ++p) {
          let py = 64 + 32 * dy;
          for (const line of Object.values(CHARSET[f[p]])) {
            for (let i = 0; i < 5; ++i) {
              if ((line & (1 << (4 - i))) != 0) {
                buf[py * this.size[1] + px + i] = 0xffffff;
              }
            }
            py++;
          }
          px += 6;
        }
      }
      return this.set(buf);
    }
    swap() {
      const tmp = this.textures.front;
      this.textures.front = this.textures.back;
      this.textures.back = tmp;
      return this;
    }
    step() {
      this.framebuffers.step.attach(this.textures.back);
      this.textures.front.bind(0);
      gl.viewport(0, 0, this.size[0], this.size[1]);
      this.programs.cellular.use()
        .attrib('quad', this.buffers.quad, 2)
        .uniformi('state', 0)
        .uniformi('f', this.t)
        .uniform('scale', this.size)
        .draw(gl.TRIANGLE_STRIP, 4);
      this.swap();
      this.t++;
      return this;
    }
    draw() {
      this.framebuffers.default.bind();
      this.textures.front.bind(0);
      gl.viewport(0, 0, this.canvas.width, this.canvas.height);
      this.programs.copy.use()
        .attrib('quad', this.buffers.quad, 2)
        .uniformi('state', 0)
        .uniform('scale', this.size)
        .draw(gl.TRIANGLE_STRIP, 4);
      return this;
    }
    get() {
      this.framebuffers.step.attach(this.textures.front);
      const rgba = new Uint8Array(this.size[0] * this.size[1] * 4);
      gl.readPixels(0, 0, this.size[0], this.size[1], gl.RGBA, gl.UNSIGNED_BYTE, rgba);
      return rgba;
    }
    compare() {
      const img = new Image;
      img.onload = (e) => {
        const c = document.createElement("canvas");
        c.width = this.size[0];
        c.height = this.size[1];
        const ctx = c.getContext("2d");
        ctx.drawImage(img, 0, 0);
        const one = ctx.getImageData(0, 0, this.size[0], this.size[1]).data;
        const two = this.get();

        const check = (one, two) => {
          for (let i = 0; i < this.size[1]; ++i) {
            for (let j = 0; j < this.size[0]; ++j) {
              for (let c = 0; c < 4; ++c) {
                const o = one[4 * (i * this.size[0] + j) + c];
                const t = two[4 * (
                  (this.size[1] - i - 1) * this.size[0] + j) + c];
                if (o != t) {
                  return false;
                }

              }

            }
          }
          return true;
        }
        document.getElementById('result').innerText =
          check(one, two) ? 'Success!' : 'Fail.';

      };
      img.src = 'data.png';
    }
    start() {
      this.timer = setInterval(function(){
        // Beware of performance :)
        for (let i = 0; i < 4; ++i) {
          if (sim.t > FRAMES) {
            clearInterval(sim.timer);
            sim.compare();
            sim = null;
            return;
          }
          sim.step();
          sim.draw();
          progress.value = sim.t;
        }
      }, 10);
      return this;
    }
}

// Main.
let sim = null;
const progress = document.getElementById('progress');
function start() {
  document.getElementById('go').addEventListener('click', (e) => {
    const flag = document.getElementById('flag').value;
    const res = document.getElementById('result');
    if (flag.replace(/[0-9A-Za-z\{\}\?\!\_\.]/gi, '') !== '') {
      res.innerText = 'Wrong format.';
      return;
    }
    if (sim !== null) {
      return;
    }
    sim = new BCA(document.getElementById('canvas'));
    sim.setState(flag);
    sim.start();
  });
}
start();
