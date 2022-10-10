/*
Copyright 2022 Google LLC

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
*/
// There is no flag here, just the background artwork.

const cfg = {
        xmax: 32,
        ymax: 32,
        ast_depth_limit: 8,
        ast_min_depth: 4,
        min_val: -64,
        max_val: 64
    },
    choice = t => t[Math.floor(Math.random() * t.length)],
    M = t => isNaN(t) ? 0 : isFinite(t) ? t < cfg.min_val ? cfg.min_val : t > cfg.max_val ? cfg.max_val : t : t > 0 ? cfg.max_val : cfg.min_val;
class EVar {
    constructor(t) {
        this.name = t
    }
    print() {
        return `${this.name}`
    }
    copy() {
        return new EVar(this.name)
    }
    evaluate(t) {
        return t[this.name]
    }
    dependencies() {
        return new Set([this.name])
    }
    equals(t) {
        return t.name === this.name
    }
    depth() {
        return 0
    }
    static random(t, e = 0) {
        return new EVar(choice(t.vars))
    }
}
class EConst {
    constructor(t) {
        this.value = t
    }
    print() {
        return `${this.quantize()}`
    }
    quantize() {
        let t = (1e3 * this.value | 0) / 1e3 + "";
        return -1 === t.indexOf(".") && (t += ".0"), t
    }
    copy() {
        return new EConst(this.value)
    }
    evaluate(t) {
        return parseFloat(this.quantize())
    }
    dependencies() {
        return new Set
    }
    depth() {
        return 0
    }
    static random(t, e = 0) {
        return new EConst(cfg.min_val + Math.random() * (cfg.max_val - cfg.min_val))
    }
}
const ARITHMETIC_OPS = {
    "+": (t, e) => M(t + e),
    "-": (t, e) => M(t - e),
    "*": (t, e) => M(t * e),
    "/": (t, e) => M(t / e),
    "%": (t, e) => M(t % e)
};
class EOp {
    constructor(t, e, r) {
        this.left_term = t, this.right_term = e, this.op = r
    }
    print() {
        return `(${this.left_term.print()} ${this.op} ${this.right_term.print()})`
    }
    copy() {
        return new EOp(this.left_term.copy(), this.right_term.copy(), this.op)
    }
    evaluate(t) {
        const e = this.left_term.evaluate(t),
            r = this.right_term.evaluate(t);
        return ARITHMETIC_OPS[this.op](e, r)
    }
    dependencies() {
        return new Set([...this.left_term.dependencies(), ...this.right_term.dependencies()])
    }
    depth() {
        return Math.max(this.left_term.depth(), this.right_term.depth()) + 1
    }
    static random(t, e = 0) {
        return new EOp(EExpr.random(t, e + 1), EExpr.random(t, e + 1), choice(Object.keys(ARITHMETIC_OPS)))
    }
}
const FUNCS = {
    sin: (t, e) => Math.sin(t, e),
    pow: (t, e) => Math.pow(t, e),
    log: (t, e) => Math.log(t, e)
};
class EMath {
    constructor(t, e, r) {
        this.left_term = t, this.right_term = e, this.func = r
    }
    print() {
        return `${func}(${this.left_term.print()}, ${this.right_term.print()})`
    }
    copy() {
        return new EMath(this.left_term.copy(), this.right_term.copy(), this.func)
    }
    evaluate(t) {
        const e = this.left_term.evaluate(t),
            r = this.right_term.evaluate(t);
        return FUNCS[this.func](e, r)
    }
    dependencies() {
        return new Set([...this.left_term.dependencies(), ...this.right_term.dependencies()])
    }
    depth() {
        return Math.max(this.left_term.depth(), this.right_term.depth()) + 1
    }
    static random(t, e = 0) {
        return new EMath(EExpr.random(t, e + 1), EExpr.random(t, e + 1), choice(Object.keys(FUNCS)))
    }
}
class EExpr {
    static random(t, e = 0) {
        const r = [EVar];
        return e <= cfg.ast_depth_limit && r.push(EOp, ETernary), e > 1 && r.push(EConst), choice(r).random(t, e + 1)
    }
}
const COMPARE_OPS = {
    "<": (t, e) => !!(t < e),
    ">": (t, e) => !!(t > e)
};
class ECompare {
    constructor(t, e, r) {
        this.left_expr = t, this.right_expr = e, this.op = r
    }
    print() {
        return `(${this.left_expr.print()} ${this.op} ${this.right_expr.print()})`
    }
    copy() {
        return new ECompare(this.left_expr.copy(), this.right_expr.copy(), this.op)
    }
    evaluate(t) {
        const e = this.left_expr.evaluate(t),
            r = this.right_expr.evaluate(t);
        return !!COMPARE_OPS[this.op](e, r)
    }
    dependencies() {
        return new Set([...this.left_expr.dependencies(), ...this.right_expr.dependencies()])
    }
    depth() {
        return Math.max(this.left_expr.depth(), this.right_expr.depth()) + 1
    }
    static random(t, e = 0) {
        return new ECompare(EExpr.random(t, e + 1), EExpr.random(t, e + 1), choice(Object.keys(COMPARE_OPS)))
    }
}
const LOGIC_OPS = {
    "||": (t, e) => !(!t && !e),
    "&&": (t, e) => !(!t || !e),
    "^": (t, e) => !!(t ^ e)
};
class ELogic {
    constructor(t, e, r) {
        this.left_expr = t, this.right_expr = e, this.op = r
    }
    print() {
        return `(${this.left_expr.print()} ${this.op} ${this.right_expr.print()})`
    }
    copy() {
        return new ELogic(this.left_expr.copy(), this.right_expr.copy(), this.op)
    }
    evaluate(t) {
        const e = this.left_expr.evaluate(t),
            r = this.right_expr.evaluate(t);
        return LOGIC_OPS[this.op](e, r)
    }
    dependencies() {
        return new Set([...this.left_expr.dependencies(), ...this.right_expr.dependencies()])
    }
    depth() {
        return Math.max(this.left_expr.depth(), this.right_expr.depth()) + 1
    }
    static random(t, e = 0) {
        return new ELogic(ECondition.random(t, e + 1), ECondition.random(t, e + 1), choice(Object.keys(LOGIC_OPS)))
    }
}
class ECondition {
    static random(t, e = 0) {
        const r = [ECompare];
        return e < cfg.ast_depth_limit && r.push(ELogic), choice(r).random(t, e + 1)
    }
}
class ETernary {
    constructor(t, e, r) {
        this.cond = t, this.true_expr = e, this.false_expr = r
    }
    print() {
        return `(${this.cond.print()} ? ${this.true_expr.print()} : ${this.false_expr.print()})`
    }
    copy() {
        return new ETernary(this.cond.copy(), this.true_expr.copy(), this.false_expr.copy())
    }
    evaluate(t) {
        return this.cond.evaluate(t) ? this.true_expr.evaluate(t) : this.false_expr.evaluate(t)
    }
    dependencies() {
        return new Set([...this.cond.dependencies(), ...this.true_expr.dependencies(), ...this.false_expr.dependencies()])
    }
    depth() {
        return Math.max(this.cond.depth(), this.true_expr.depth(), this.false_expr.depth()) + 1
    }
    static random(t, e = 0) {
        for (;;) {
            const r = ECondition.random(t, e + 1),
                n = EExpr.random(t, e + 1),
                i = EExpr.random(t, e + 1),
                s = new ETernary(r, n, i);
            if (Array.from(s.dependencies()).sort().join("") == Array.from(t.vars).sort().join("")) return s
        }
    }
}
class EProgram {
    constructor(t, e) {
        this.conf = t, this.exprs = e
    }
    print() {
        const t = [];
        for (const e of Object.values(this.conf.vals)) t.push(`${e} = ${this.exprs[e].print()};`);
        return t.join("\n")
    }
    execute(t) {
        const e = {};
        for (const r of Object.values(this.conf.vals)) e[r] = this.exprs[r].evaluate(t);
        for (const [t, r] of Object.entries(e)) e[t] = M(e[t]);
        return e
    }
    static random(t) {
        const e = {},
            r = () => {
                let e = null;
                for (;;) {
                    if (e = EExpr.random(t), e.depth() < cfg.ast_min_depth) continue;
                    const r = {};
                    for (let t = 0; t < 16; ++t) r[t] = 0;
                    for (let n = 0; n < 128; ++n) {
                        const n = {};
                        for (const e of Object.values(t.vars)) n[e] = cfg.min_val + Math.random() * (cfg.max_val - cfg.min_val);
                        r[16 * M(e.evaluate(n)) | 0] += 1
                    }
                    let n = 0;
                    for (const t of Object.values(r)) 0 != t && n++;
                    if (!(n < 4)) break
                }
                return e
            };
        for (const n of Object.values(t.vals)) e[n] = r();
        return new EProgram(t, e)
    }
}
window.onload = function(t) {
    let i = 0,
        s = null,
        a = EProgram.random({
            vars: "xyvw",
            vals: "vwbcd"
        });
      const draw = () => {
        r.fillStyle = "rgb(180, 190, 210)", 
        r.fillRect(0, 0, e.width, e.height), 
        i % 120 == 0 && (s = a, a = EProgram.random({
            vars: "xyvw",
            vals: "vwbcd"
        }));
        const t = (t, e, r) => t + (e - t) * r;
        let n = 0,
            c = 0,
            h = 0,
            o = 0;
        for (let p = 0; p < cfg.ymax; ++p)
            for (let l = 0; l < cfg.xmax && !(l > p); ++l) {
                const d = s.execute({
                    x: cfg.min_val + (cfg.max_val - cfg.min_val) * l / cfg.xmax,
                    y: cfg.min_val + (cfg.max_val - cfg.min_val) * p / cfg.ymax,
                    v: n,
                    w: h
                });
                n = d.v, h = d.w;
                const m = a.execute({
                    x: cfg.min_val + (cfg.max_val - cfg.min_val) * l / cfg.xmax,
                    y: cfg.min_val + (cfg.max_val - cfg.min_val) * p / cfg.ymax,
                    v: c,
                    w: o
                });
                c = m.v, o = m.w;
                const u = i % 120 / 120,
                    _ = {
                        x: l * e.width / cfg.xmax,
                        y: p * e.height / cfg.ymax
                    },
                    f = Math.abs(t(d.d, m.d, u)),
                    x = Math.max(Math.min(160, 16 * f), 128);
                r.fillStyle = `rgb(${x-16}, ${x-8}, ${x})`, 
                r.fillRect(_.x, _.y, t(d.b, m.b, u), t(d.c, m.c, u)), 
                r.fillRect(e.width - _.x, e.height - _.y, t(d.c, m.c, u), t(d.b, m.b, u))
            }
        i++
    };
    const e = document.getElementById("background-canvas"),
        r = e.getContext("2d"),
        n = () => {
            e.width = window.innerWidth, e.height = window.innerHeight;
            draw();
        };
    n(), window.addEventListener("resize", n);

    setInterval(draw, 1e3 / 60);
};
