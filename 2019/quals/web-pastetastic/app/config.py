# Copyright 2019 Google LLC
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

import json

CORE_DEPENDENCIES = [
  {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-core.min.js',
    'integrity': 'sha256-sSTatLHEEY8GQrdYAuhkqrYogKZ/jDlgfYaqK3ld/uQ=',
  },
  {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/marked/0.6.1/marked.min.js',
    'integrity': 'sha256-Y0YX22e5n0zVSAd1tJ6aypkv9o4AEX5YcRKPg1Al8jg=',
  },
]

LANGUAGE_PLUGINS = {
  'actionscript': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-actionscript.min.js',
    'integrity': 'sha256-XDKLLq1uv8yATcsO172Z1MOoDOlbXk75LyPb7EQbwAk=',
    'requires': ['javascript']
  },
  'ada': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-ada.min.js',
    'integrity': 'sha256-lNxf/WmtaYUhVP+R0Ds04RRZ3hZIA39NlW5VgjWvDrU=',
  },
  'applescript': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-applescript.min.js',
    'integrity': 'sha256-F3LNnnxVV4AYdmhr9rKaejJ+RJhGsoVKF8iw8iL2HIw=',
  },
  'arduino': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-arduino.min.js',
    'integrity': 'sha256-qpBYb63n+L9P3FIsrHv8KhGYq1RI2sc5c2cv28CsYhY=',
    'requires': ['cpp']
  },
  'asm6502': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-asm6502.min.js',
    'integrity': 'sha256-TdIFG+vWWwpUct6X1WfeQJI4GGb/vlAsG+q8bCrUrjE=',
  },
  'aspnet': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-aspnet.min.js',
    'integrity': 'sha256-BWXRjIuZGWCYtsmPy2D1SA+CbXo3VQKig0J7YTGWRj4=',
    'requires': ['markup']
  },
  'bash': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-bash.min.js',
    'integrity': 'sha256-0W9ddRPtgrjvZVUxGhU/ShLxFi3WGNV2T7A7bBTuDWo=',
  },
  'basic': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-basic.min.js',
    'integrity': 'sha256-/iAxh3XPkx7guWsx0JLVTwG/kvDGiONOXwSjMnQ47ps=',
  },
  'bison': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-bison.min.js',
    'integrity': 'sha256-zdd9vxPy6Z1MopkjyXFc7FeL31V2jfzunDyotdCTeBY=',
    'requires': ['c']
  },
  'brainfuck': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-brainfuck.min.js',
    'integrity': 'sha256-VMnAWpm0qsoKYhwjGWpbpIFoEqmKFqgRMvrsPe4SLA8=',
  },
  'c': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-c.min.js',
    'integrity': 'sha256-GUSDFW3k9NM7UWf4Itg/w8lO7pSQznTzo22QgwuMfVM=',
    'requires': ['clike']
  },
  'cil': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-cil.min.js',
    'integrity': 'sha256-1P5I9/D3qxSN6XKl9nakXH50C8oIHk95Qxh8o30IX5o=',
  },
  'clike': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-clike.min.js',
    'integrity': 'sha256-yLywlZBInSTeO8eTUtLZ9QQHOmG5xwT+FfEIjjMC8RU=',
  },
  'clojure': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-clojure.min.js',
    'integrity': 'sha256-HN4MXj6IcoKmLjpkeFAMHa4Q7SsqQdzWkbI85CdHOac=',
  },
  'cmake': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-cmake.min.js',
    'integrity': 'sha256-Qjmwi+jZhg+v3TUo7c5z7Xxd3xVMvsOxl7e+MnorD/4=',
  },
  'coffeescript': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-coffeescript.min.js',
    'integrity': 'sha256-WmDHGDrlScE7RS4XVlXeTh8q/NvuOizEOH6p4SExV9k=',
  },
  'cpp': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-cpp.min.js',
    'integrity': 'sha256-7yMNzez7zed7A47fTdjYNtDNKW6EU5zi7Uk7ZoyurNA=',
    'requires': ['c']
  },
  'crystal': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-crystal.min.js',
    'integrity': 'sha256-6JDP9F+HEzjPPiWpmaSAk6w2JFs9s81MlVeWbaWW8W4=',
  },
  'csharp': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-csharp.min.js',
    'integrity': 'sha256-W+nkLYdja/ZJWhoahOJMsmK6swkfzTtIQRlKyv/4Jx4=',
    'requires': ['clike']
  },
  'css': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-css.min.js',
    'integrity': 'sha256-49Y45o2obU1Yv4zkYDpMDyAa+D9sgKNbNy4ZYGRl/ls=',
  },
  'd': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-d.min.js',
    'integrity': 'sha256-bk7lVu6vMJNqTgcIj5QAPURt4aMhOtZuKrcDjgKEOjU=',
    'requires': ['clike']
  },
  'dart': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-dart.min.js',
    'integrity': 'sha256-1rI2gSHAI+1zU2T/qFCGD2XVXHfR4p5vjpma5LR3KFQ=',
    'requires': ['clike']
  },
  'diff': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-diff.min.js',
    'integrity': 'sha256-2j19IpsajXc3FKagWaOLYxCvNv13NmR4mMP749TMBxg=',
  },
  'erb': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-erb.min.js',
    'integrity': 'sha256-a3LUkP+U0/upYKDwxeKylQPoMuvRJI8ugle49HgFhmg=',
    'requires': ['ruby']
  },
  'erlang': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-erlang.min.js',
    'integrity': 'sha256-8O/rweaGW1tOoTYWQvu7a0ALsJ4USC9EGphsGuyB7WQ=',
  },
  'fortran': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-fortran.min.js',
    'integrity': 'sha256-fGA7+D1LeRxTJQWlItOVzD0IXQIAigH0F7qmmyFjLko=',
  },
  'fsharp': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-fsharp.min.js',
    'integrity': 'sha256-kFgdzdJlTG3iRggIHeCRSee0l5wuig+4zKFDhlipoUQ=',
    'requires': ['clike']
  },
  'git': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-git.min.js',
    'integrity': 'sha256-8J6flH/bvIH0PaeXKSx1V6fzaN0auFyTubqXL90ViIs=',
  },
  'glsl': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-glsl.min.js',
    'integrity': 'sha256-Zy9XC7Aw6NOgIaR2viUyXI8uQPakPFm0P67q9ijfhVU=',
    'requires': ['clike']
  },
  'go': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-go.min.js',
    'integrity': 'sha256-0gPlDXMlahNpCwHdKGf6TkjpLCXUS7mliN3nmbKOBCc=',
    'requires': ['clike']
  },
  'graphql': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-graphql.min.js',
    'integrity': 'sha256-OdTLWlUT4+uAiTOS5uf9gChAsADKtOHFgzhybAEc9I4=',
  },
  'groovy': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-groovy.min.js',
    'integrity': 'sha256-ori+xD+EJF521Mm5jzmBSi0v7a8JhfYWTyPceaRwn88=',
    'requires': ['clike']
  },
  'haskell': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-haskell.min.js',
    'integrity': 'sha256-OIvqHXM5UVQAlCLLbb6tkbAg+R3UiCHRssAUPeqr7ao=',
  },
  'http': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-http.min.js',
    'integrity': 'sha256-TT0aUWucEz9ERKYpzbpz+xjCaBwfhAQLsmWLhiemPJI=',
  },
  'java': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-java.min.js',
    'integrity': 'sha256-xkjfLarZfrNcxmgjDVE2XGj4/OIti0A0+HMRz8fg1rI=',
    'requires': ['clike'],
  },
  'javadoc': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-javadoc.min.js',
    'integrity': 'sha256-VH6tsuQPtcw/sMyG455EAqxAIaYOVsRQwkke6BKwYcs=',
  },
  'javascript': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-javascript.min.js',
    'integrity': 'sha256-KxieZ8/m0L2wDwOE1+F76U3TMFw4wc55EzHvzTC6Ej8=',
    'requires': ['clike']
  },
  'javastacktrace': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-javastacktrace.min.js',
    'integrity': 'sha256-tJDVY7vlGKeEVmQ79x/G86sbN86a6eKm2BwEFJ++B6w=',
  },
  'jsdoc': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-jsdoc.min.js',
    'integrity': 'sha256-Z70lGjKwHp4+bggv2pZglmPrjW6l9TZWG5yQE9Mo0EY=',
  },
  'json': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-json.min.js',
    'integrity': 'sha256-18m89UBQcWGjPHHo64UD+sQx4SpMxiRI1F0MbefKXWw=',
  },
  'jsx': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-jsx.min.js',
    'integrity': 'sha256-oKM5pXZjDLVh12SHSa1wtIJV0zF49TOwu+jbqkDfYZA=',
  },
  'julia': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-julia.min.js',
    'integrity': 'sha256-eKXQhHu0IjpzjiQVHa1PqloCsn5XxrLHEovEwkdOpx8=',
  },
  'kotlin': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-kotlin.min.js',
    'integrity': 'sha256-UVVPaOGx3GBfzl/v/ZjLlEJ9xoN4pSgYNmtmWx5HCZc=',
  },
  'latex': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-latex.min.js',
    'integrity': 'sha256-X4kboLjwRBUNvyd5mVUoHKyxW7bMumvi63mGU2kEtLA=',
  },
  'less': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-less.min.js',
    'integrity': 'sha256-KPVJREIAtbHDIVFzCC2CG/+kFJvS2QSvheijs7hzKyI=',
    'requires': ['css']
  },
  'lisp': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-lisp.min.js',
    'integrity': 'sha256-JF0oYD0ce6QwJwhkk2l2LpPW9/+nMUVKgyfQZwKgL7o=',
  },
  'lua': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-lua.min.js',
    'integrity': 'sha256-dtM544asCSWgnGEtFfy0Up/RZ1sIKPwIm1efm4DTF2g=',
  },
  'makefile': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-makefile.min.js',
    'integrity': 'sha256-pbm9rQGN4Ore8f63Nc0XohO/ndkqmaCkiM+t++tZS6s=',
  },
  'markdown': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-markdown.min.js',
    'integrity': 'sha256-e4izlzFmEQlenZQnzkYK5oyxV5mX6lwVQjL6onkHiy0=',
    'requires': ['markup']
  },
  'markup': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-markup.min.js',
    'integrity': 'sha256-8nT1E50WC5TDeb3+USsFEXN5ZGgLdmwZ6RS5KT71Wjs=',
  },
  'matlab': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-matlab.min.js',
    'integrity': 'sha256-Eii4kMdOE8ezFgaPuk3EEIx8XTzoFELWqTeSAzzFNzg=',
  },
  'nasm': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-nasm.min.js',
    'integrity': 'sha256-q25WpTTIWYOfZSv8lthBMxjDdyxBgbpg8VkUbNvs0r0=',
  },
  'objectivec': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-objectivec.min.js',
    'integrity': 'sha256-PdzihI/De5LLXlXeap1/ii5CduyVtr8dJByxPw9mZfY=',
    'requires': ['c']
  },
  'ocaml': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-ocaml.min.js',
    'integrity': 'sha256-r93j2XbuUKMLy7BOj1rGro++GLf6G1q12Z80zlza6I0=',
  },
  'opencl': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-opencl.min.js',
    'integrity': 'sha256-fWZd1X/MgB03plUc1TS+3gPr+dX7VAJgUli3e/dSHPs=',
  },
  'parigp': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-parigp.min.js',
    'integrity': 'sha256-o3zIbQfZLv4s9vvCxk053vJogsMpoyl/4kHUFUSeX2E=',
  },
  'pascal': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-pascal.min.js',
    'integrity': 'sha256-+ZydA8Nld4ARjQ20Xg1GdqPITRR+O54ChikNpWbjNNQ=',
  },
  'perl': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-perl.min.js',
    'integrity': 'sha256-4UrzdEz2XhP7GUL8C3p5EvYqk+VX3N0GDZO01qhqSuc=',
  },
  'php': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-php.min.js',
    'integrity': 'sha256-gJj4RKQeXyXlVFu2I8jQACQZsii/YzVMhcDT99lr45I=',
  },
  'plsql': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-plsql.min.js',
    'integrity': 'sha256-OsVeLk13RgKzb0xXIW8fXxmdfeOviRALmOdgOx6lwVk=',
    'requires': ['sql'],
  },
  'powershell': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-powershell.min.js',
    'integrity': 'sha256-sADd0pgdCd3YpzQBaaIBhB/f3wEHjhUPQKZXVwAGxC8=',
  },
  'processing': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-processing.min.js',
    'integrity': 'sha256-+uj4GjS/1qvSEc6jTuFiDyfY+WoZEQqXDxR3/NPU1xA=',
    'requires': ['clike']
  },
  'prolog': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-prolog.min.js',
    'integrity': 'sha256-kRo6aBwWmcA13drxjM/5J+lj1c9rBOPXbzZZ/RVzZVk=',
  },
  'protobuf': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-protobuf.min.js',
    'integrity': 'sha256-mbfGZEOjT4PX0OwC+Om2vTe8UsVDM2l8bnkFGCzC3CM=',
    'requires': ['clike']
  },
  'python': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-python.min.js',
    'integrity': 'sha256-zXSwQE9cCZ8HHjjOoy6sDGyl5/3i2VFAxU8XxJWfhC0=',
  },
  'r': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-r.min.js',
    'integrity': 'sha256-gL4dWWDK5a/PMVeldvL97FJDRISGr4d0n7B09bSZRhc=',
  },
  'regex': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-regex.min.js',
    'integrity': 'sha256-YyOLni8cJbmQXM1FG50N3JAVfuTltcZGJwEmCeueaKA=',
  },
  'ruby': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-ruby.min.js',
    'integrity': 'sha256-SGBXZakPP3Fv0P4U6jksuwZQU5FlC22ZAANstHSSp3k=',
  },
  'rust': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-rust.min.js',
    'integrity': 'sha256-iLvA6WoUo1szBgKU5uTNOyWYA+to/92tUFM9GkdFpfs=',
  },
  'sass': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-sass.min.js',
    'integrity': 'sha256-3oigyyaPovKMS9Ktg4ahAD1R6fOSMGASuA03DT8IrvU=',
  },
  'scala': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-scala.min.js',
    'integrity': 'sha256-n7yE0wXXe/CGgSU2Lht6OSaAuPpX1SNhmaxDOUvxLZs=',
    'requires': ['java']
  },
  'scheme': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-scheme.min.js',
    'integrity': 'sha256-wagePCH0Bf8H2NJL6NLvfAo/E28vBpfmaWHQmTwlPbs=',
  },
  'scss': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-scss.min.js',
    'integrity': 'sha256-e8D5SrALfYOcy2NqfpblBaRTuTlrmQUP6RUOYtQ+7cg=',
    'requires': ['css']
  },
  'smalltalk': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-smalltalk.min.js',
    'integrity': 'sha256-tpLhvRyan+a4VJcIBS18K1amTQ+D6Mw6Q1kpOmra1tw=',
  },
  'soy': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-soy.min.js',
    'integrity': 'sha256-qUzL3S+AgXekMp0tB9fcM3+hcmilzf/HE1PWKSRFIEA=',
  },
  'sql': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-sql.min.js',
    'integrity': 'sha256-zgHnuWPEbzVKrT72LUtMObJgbwkv0VESwRfz7jpdsq0=',
  },
  'swift': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-swift.min.js',
    'integrity': 'sha256-udcKTdu6vw1GzcaC0kwzPE/1zKYBbmjr0mY8A27Xb3g=',
    'requires': ['clike']
  },
  'textile': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-textile.min.js',
    'integrity': 'sha256-UMjpaRB1IUP+4VrYhWpZJVcGIFK9K06oxUz5EYcbzSY=',
  },
  'toml': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-toml.min.js',
    'integrity': 'sha256-9MnngneIB3TwEPWioOI6snULEeN7wHLq2+einu+TvGE=',
  },
  'tsx': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-tsx.min.js',
    'integrity': 'sha256-Lu/zMuTtme4f+TbQrXMjj8OQwAb0x4RApaysYdeJBN0=',
    'requires': ['jsx']
  },
  'typescript': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-typescript.min.js',
    'integrity': 'sha256-4ZOSQ1LXG14Swa26SUt2L/IfrwVPjrsvQNLxQiIPi8U=',
    'requires': ['javascript']
  },
  'vbnet': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-vbnet.min.js',
    'integrity': 'sha256-OWa6yCZT+20Xdho9LQYjDfwXaQQByFg1/MpPPQmJ7vM=',
    'requires': ['basic']
  },
  'verilog': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-verilog.min.js',
    'integrity': 'sha256-EhZ68Nu/SZGYROzlrpDlaiUs3ByOHHiWTCTLkO0bkIw=',
  },
  'vhdl': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-vhdl.min.js',
    'integrity': 'sha256-DlOnP3cvuVRpTGGcymNNfTV+bf/uy433DNPyU3iP9Rg=',
  },
  'vim': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-vim.min.js',
    'integrity': 'sha256-p+JJVLKpQLg+ugkH9NG9zBgEt4oq79ZJqyljl4/o6IY=',
  },
  'visual-basic': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-visual-basic.min.js',
    'integrity': 'sha256-V5pPeBgeL9OcMsfpcX8zt4nTZVWj17fQVvnS0KVO/hY=',
  },
  'wasm': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-wasm.min.js',
    'integrity': 'sha256-2i14hUSVIGaulLSxLQ/yUt0zt+JCyA8UmHxh3EyY05E=',
  },
  'wiki': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-wiki.min.js',
    'integrity': 'sha256-V14zvplc141S9y2zyDUqpj0ZoXobDwP/wYK91ALcAs8=',
    'requires': ['markup']
  },
  'yaml': {
    'src': 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.16.0/components/prism-yaml.min.js',
    'integrity': 'sha256-JoqiKM2GipZjbGjNyl62d6qjQY1F9QTLriWOe4N76wE=',
  },
}

PRELOAD_PLUGINS = ['markup', 'javascript', 'css', 'java', 'cpp', 'c']


def buildCreateConfig(preload_lang):
  preload = set(PRELOAD_PLUGINS)
  if preload_lang is not None:
    preload.add(preload_lang)
  config = {
      'viewer': [
          {
              'dependencies': CORE_DEPENDENCIES,
              'plugins': LANGUAGE_PLUGINS,
              'preload': [l for l in preload]
          },
      ],
  }
  return json.dumps(config, separators=(',', ':'), sort_keys=True)


def expandRequires(lang):
  plugin = LANGUAGE_PLUGINS[lang]
  if 'requires' in plugin:
    for r in plugin['requires']:
      yield r
      for r2 in expandRequires(r):
        yield r2


def buildViewConfig(lang):
  plugins = set()
  plugins.add(lang)
  for r in expandRequires(lang):
    plugins.add(r)
  config = {
      'viewer': [
          {
              'dependencies': CORE_DEPENDENCIES,
              'plugins': {l: LANGUAGE_PLUGINS[l] for l in plugins},
              'preload': [lang],
          },
      ],
  }
  return json.dumps(config, separators=(',', ':'), sort_keys=True)


def coercePluginLang(lang):
  if len(lang) > 0 and lang in LANGUAGE_PLUGINS:
    return lang
  return None


def validatePluginLang(lang):
  if coercePluginLang(lang) is None:
    raise Exception('Unsupported language')
