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

function flag_encode() {
  var flag = 'W0w_5ucH_N1c3_d3bU9_sK1lLz_';
  // Encode
  var a = 0;
  var i = 13337;
  var result = [];
  var pool = Array.from(Array(flag.length).keys());
  while (pool.length > 0) result[pool.splice((i = (i || 1) * 16807 % 2147483647)%pool.length, 1)[0]] = flag[a++];
  var encoded_flag = result.join('')
  console.log('encoded_flag', encoded_flag)
  // Decode as test
  var pool = encoded_flag.split('');
  var i = 13337;
  var result = '';
  while (pool.length > 0) result += pool.splice((i = (i || 1) * 16807 % 2147483647)%pool.length, 1)[0];
  console.log('decoded flag', result);
}

let hostFn = s => {  
  let result = '';
  let x = 0;
  try {
    for (let x = 0; x+3 <= s.length; x+=3) {
      let next =
        (s.charCodeAt(x)%2)*64 +
        (s.charCodeAt(x+1)%8)*8 +
        s.charCodeAt(x+2)%8;
      next = Math.min(Math.max(0x20, next), 0x7E);
      result += String.fromCharCode(next);
    }
    return result;
  } catch(_) {
    throw ChecksumError(s, result, x);
  }
}

function encode(c, background) {
    background = background || (() => 0x2000);
    let output = '';
    for (let x = 0; x < c.length; x++) {
        output += String.fromCharCode(((background(x*3)>>3)<<3) + ((c.charCodeAt(x) >> 6) & 1));
        output += String.fromCharCode(((background(x*3+1)>>3)<<3) + ((c.charCodeAt(x) >> 3) & 7));
        output += String.fromCharCode(((background(x*3+2)>>3)<<3) + (c.charCodeAt(x) & 7));
    }
    return output;
}

// Not all hostPrefix lengths work!!!
// Import jsTokens to the global namespace before using
// https://github.com/lydell/js-tokens
function generate(hostPrefix, host, code) {
    let lines = host.split('\n').slice(0, -1);
    let hostPaddedLength = lines.reduce((x,l)=>x + Math.floor((l.length + 1) / 3) * 3, 0);
    let charsNeeded = hostPaddedLength + (lines.length * 4 + code.length) * 3;
    let extraLength = 0;
    let tokens, output;
    do {
        let lineWidth = Math.ceil(charsNeeded / lines.length);
        lineWidth = Math.ceil(lineWidth / 3 + (extraLength++)) * 3;
        console.log(lineWidth);
        output = '';
        tokens = Array.from(jsTokens(code), (token)=>token.value);
        for (let x = 0; x < lines.length; x++) {
            let line = lines[x];
            let prefix = x == 0 ? ':' : '*/';
            let postfix = x == lines.length - 1 ? '//' : '/*'
            let padding = ' '.repeat(Math.ceil(line.length / 3) * 3 - line.length);
            let newLine = line + padding + encode(prefix);
            let available = (lineWidth - newLine.length - (x != 0 ? 0 : hostPrefix.length)) / 3 - 1 - postfix.length;
            while (tokens.length > 0 && tokens[0].length <= available) {
                let token = tokens.shift();
                newLine += encode(token);
                available -= token.length;
            }
            newLine += encode(postfix);
            newLine += ' '.repeat(available * 3)
            newLine += '  \n';
            output += newLine;
        }
        output += '}';
    } while (tokens.length != 0);
    console.log(output);
    console.log(checksum(output))
}

do
  x = encode('"),i+=(x+"").length+12513|1,!("', x => Math.max(32,Math.floor(Math.random()*127)));
while(x.includes('"') || x.includes('`') || x.includes('\\'))
console.log(x);

payload = "Object.defineProperty(document.body,'className',{get(){return this.getAttribute('class')||''},set(x){this.setAttribute('class',(x!='granted'||(/^CTF{([0-9a-zA-Z_@!?-]+)}$/.exec(keyhole.value)||x)[1].endsWith('Br0w53R_Bu9s_C4Nt_s70p_Y0u'))?x:'denied')}})";
generate('checksum  = ', ' ' + hostFn, payload);
