// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.



/**
 * @param {string} text
 * @return {string}
 */
function removeComments(text) {
  return text.replace(/\s*;.*/g, '');
}

/**
 * @param {string} text
 * @return {string}
 */
function getDataSection(text) {
  return text.match(/(?:^|\n)[.]data\r?\n([\s\S]*)(?=\n[.]code\r?\n)/i)[1];
}

/**
 * @param {string} text
 * @return {string}
 */
function getCodeSection(text) {
  return text.match(/(?:^|\n)[.]code\r?\n([\s\S]*)/i)[1];
}

/**
 * @param {string} text
 * @return {!Array<string>}
 */
function getCodeSectionLabels(text) {
  return text.match(/[&][a-z]+/ig).reduce(function(obj, label) {
    obj[label] = label;
    return obj;
  }, {});
}

/**
 * @param {number} number
 * @return {!Array<number>}
 */
function int32Encode(number) {
  return Array.from(new Uint8Array(new Int32Array([number]).buffer));
}

/**
 * @param {number} number
 * @return {!Array<number>}
 */
function float64Encode(number) {
  return Array.from(new Uint8Array(new Float64Array([number]).buffer));
}

/**
 * @param {string} str
 * @return {!Array<number>}
 */
function utf16Encode(str) {
  return String(str).split('').reduce(function(arr, char) {
    var c = char.charCodeAt();
    return arr.concat([c & 0xFF, c >> 8]);
  }, []);
}

/**
 * @param {string} str
 * @return {!Array<number>}
 */
function encodeString(str) {
  return [].concat.apply(int32Encode(str.length), utf16Encode(str));
}

/**
 * @param {string} text
 * @return {{offset:number,labels:!Object<string,!Uint32Array>,encoded:string}}
 */
function parseDataSection(text) {
  var offset = 1;
  var labels = {};
  var encoded = '';
  var index = 1;
  String(text).replace(
      /^\s*([$][a-z]+)\s+(string|int|float|mem)\s+(.*)/img,
      function(_, label, type, data) {
        var bytes = [];
        switch (type) {
          case 'string':
            bytes = [8].concat(encodeString(data));
            break;
          case 'int':
            bytes = [4].concat(int32Encode(data | 0));
            break;
          case 'float':
            bytes = [7].concat(float64Encode(Number(data)));
            break;
          case 'mem':
            for (let i = 0; i < Number(data); i += 4) {
              bytes.push(0, 0, 0x7F, 0x7F);
            }
            break;
          default:
            throw new Error('Error parsing ' + _);
        }
        // align to 4 bytes
        var padding = 4 - bytes.length % 4;
        for (let i = 0; i < padding; i++) {
          bytes.push([0x7F]);
        }
        labels[label] = new Uint32Array([index++]);
        offset += bytes.length / 4;
        encoded += escape(String.fromCharCode.apply(String, bytes));
      });
  return {
    code: text,
    offset: offset * 4,
    labels: labels,
    encoded: encoded,
  };
}

/**
 * @param {string} text
 * @param {{offset:number,labels:!Object<string,!Uint32Array>,encoded:string}} data
 * @return {{encoded:string}}
 */
function parseCodeSection(text, data) {
  var labels = getCodeSectionLabels(text);
  var bytes = [];
  for (var label in labels) {
    data.labels[label] = new Uint32Array([0]);
  }
  var offset = 0;
  String(text).replace(
      /^\s*(?:([&][a-z]+):|([a-z]{3})\s+(?:(int|float)?\s*(\S+))(?:\s*(?:(int|float|string)?\s*(.+))))/img,
      function(
          _, labelDef, instruction, constantType, valueOrLabel, constantType2,
          valueOrLabel2) {
        if (labelDef) {
          data.labels[labelDef].set([data.offset / 4 + offset]);
        } else {
          var opCode = instructions.indexOf(instruction);
          if (opCode < 0) {
            throw new Error('Invalid instruction ' + instruction + ' in ' + _);
          }
          bytes.push([opCode]);
          function parseArgument(
              constantType, valueOrLabel, labelsArePointers) {
            switch (constantType) {
              case 'int':
                bytes.push([4], int32Encode(valueOrLabel));
                break;
              case 'float':
                bytes.push([7], float64Encode(valueOrLabel));
                break;
              case 'string':
                bytes.push([8], encodeString(valueOrLabel));
                break;
              default:
                bytes.push(
                    [(labelsArePointers ? 128 : 0) + 5],  // pointer
                    new Uint8Array(data.labels[valueOrLabel].buffer));
            }
          }
          parseArgument(constantType, valueOrLabel, false);
          parseArgument(constantType2, valueOrLabel2, true);
          offset++;
        }
      });
  var encoded = escape(String.fromCharCode.apply(
      String, [].concat.apply([], bytes.map(function(elem) {
        return Array.from(elem);
      }))));
  return {
    code: text,
    data: data,
    labels: labels,
    bytes: bytes,
    offset: offset,
    encoded: encoded
  };
}

/**
 * @param {string} text
 * @return {{program: !Uint8Array}}
 */
function assemble(text) {
  var clean = removeComments(text);
  var data = parseDataSection(getDataSection(clean));
  var code = parseCodeSection(getCodeSection(clean), data);
  var program =
      [
        unescape(data.encoded),
        unescape(code.encoded),
      ].join('')
          .split('')
          .map(function(c) {
            return c.charCodeAt();
          });
  var paddedProgram =
      new Uint8Array(
          [].concat(
              // data offset
              Array.from(new Uint8Array(new Uint32Array([data.offset]).buffer)),
              // program
              Array.from(program),
              // padding
              new Array(1 + 4 - program.length % 4).join('0').split('')))
          .buffer;
  return {
    program: paddedProgram,
    sections: {
      data: data,
      code: code,
    },
  };
}

/**
 * @param {string} text
 * @return {!Uint8Array}
 */
_compile = function(text) {
  return assemble(text).program;
};
