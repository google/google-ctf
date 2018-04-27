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
 * @param {string} e
 * @extends Error
 * @constructor
 */
var VMError = function(e) {
  Error.call(this, e);
};
VMError.prototype = Error.prototype;

/**
 * @type {!Array<string>}
 */
var types = [
  'Int8', 'Uint8', 'Int16', 'Uint16', 'Int32', 'Uint32', 'Float32', 'Float64',
  '_String',  // read only
];

/**
 * @param {!ArrayBuffer} buffer
 * @param {number} byteOffset
 * @param {number} byteLength
 * @extends Array
 * @constructor
 */
_StringArray = function(buffer, byteOffset, byteLength) {
  this.buffer = buffer;
  this.byteOffset = byteOffset || 0;
  this.byteLength = byteLength || buffer.byteLength - this.byteOffset;
  var view = new DataView(buffer, byteOffset, byteLength);
  for (var stringLength, i = 0; i < view.byteLength;
       i += 4 + 2 * stringLength) {
    stringLength = view.getUint32(this.byteOffset, true);
    try {
      this.push(String.fromCharCode.apply(
          String,
          Array.from(new Uint16Array(view.buffer.slice(
              this.byteOffset + i + 4,
              this.byteOffset + i + 4 + stringLength * 2)))));
    } catch (e) {
      break;
    }
  }
};
_StringArray.prototype = [];

/**
 * @param {!ArrayBuffer} buffer
 * @return {{value:*,newOffset:number}}
 */
function consumeValue(buffer) {
  var bytes = new Uint8Array(buffer);
  var tag = bytes[0] & 0x7F;
  var pointer = bytes[0] >> 7;
  var type = types[tag];
  var value;
  if (type) {
    var bitSize = type.replace(/\D+/g, '');
    var end;
    if (bitSize) {
      end = 1 + bitSize / 8;
    }
    var view = new self[type + 'Array'](buffer.slice(1, end));
    if (!bitSize) {
      bitSize = 32 + 16 * view[0].length;
    }
    if (pointer) {
      value = function(memory) {
        return memory[view[0]];
      };
    } else {
      value = view[0];
    }
    var newBuffer = new Uint8Array(buffer.slice(1 + bitSize / 8));
    var paddingLength = 0;
    while (newBuffer[paddingLength] === 0x7F) {
      paddingLength++;
    }
    return {
      value: value,
      newOffset: 1 + bitSize / 8 + paddingLength,
    };
  }
  throw new VMError('Invalid Type');
}

/**
 * @param {*} value
 * @param {!Array} memory
 * @return {*}
 */
function getValue(value, memory) {
  try {
    return getValue(value(memory), memory);
  } catch (e) {
    return value;
  }
}

/**
 * @param {*} input
 * @return {*} out
 */
function _stdin(input) {
  // replace me
}


/**
 * @param {*} input
 * @return {*} out
 */
function _stdout(input) {
  // replace me
}


/**
 * @param {*} input
 * @return {*} out
 */
function _stderr(input) {
  // replace me
}

/**
 * @type {!Array<function(*):*>}
 */
var fds = [
  function(d) {
    return _stdin(d);
  },
  function(d) {
    return _stdout(d);
  },
  function(d) {
    return _stderr(d);
  },
];

var keepGoing = {};

/**
 * @param {!ArrayBuffer} buffer
 * @return {{value:*,newOffset:number}}
 */
function consumeInstruction(buffer) {
  var bytes = new Uint8Array(buffer);
  var instruction = instructions[bytes[0]];
  var value, newOffset;
  var to = consumeValue(buffer.slice(1));
  var aux = consumeValue(buffer.slice(1 + to.newOffset));
  newOffset = 1 + to.newOffset + aux.newOffset;
  switch (instruction) {
    case 'mov':
      value = function(memory) {
        memory[getValue(to.value, memory)] = getValue(aux.value, memory);
        return keepGoing;
      };
      break;
    case 'cmp':
      value = function(memory) {
        var a = memory[getValue(to.value, memory)];
        var b = getValue(aux.value, memory);
        memory[getValue(to.value, memory)] = a === b;
        return keepGoing;
      };
      break;
    case 'jlz':
      value = function(memory) {
        if (getValue(aux.value, memory) < 0) {
          return memory[getValue(to.value, memory)](memory);
        }
        return keepGoing;
      };
      break;
    case 'jgz':
      value = function(memory) {
        if (getValue(aux.value, memory) > 0) {
          return memory[getValue(to.value, memory)](memory);
        }
        return keepGoing;
      };
      break;
    case 'jez':
      value = function(memory) {
        if (getValue(aux.value, memory) === 0) {
          return memory[getValue(to.value, memory)](memory);
        }
        return keepGoing;
      };
      break;
    case 'jnz':
      value = function(memory) {
        if (getValue(aux.value, memory) !== 0) {
          return memory[getValue(to.value, memory)](memory);
        }
        return keepGoing;
      };
      break;
    case 'ret':
      value = function(memory) {
        return memory[getValue(to.value, memory)];
      };
      break;
    case 'add':
      value = function(memory) {
        memory[getValue(to.value, memory)] += getValue(aux.value, memory);
        return keepGoing;
      };
      break;
    case 'sub':
      value = function(memory) {
        memory[getValue(to.value, memory)] -= getValue(aux.value, memory);
        return keepGoing;
      };
      break;
    case 'mul':
      value = function(memory) {
        memory[getValue(to.value, memory)] *= getValue(aux.value, memory);
        return keepGoing;
      };
      break;
    case 'div':
      value = function(memory) {
        memory[getValue(to.value, memory)] /= getValue(aux.value, memory);
        return keepGoing;
      };
      break;
    case 'mod':
      value = function(memory) {
        memory[getValue(to.value, memory)] %= getValue(aux.value, memory);
        return keepGoing;
      };
      break;
    case 'and':
      value = function(memory) {
        memory[getValue(to.value, memory)] &= getValue(aux.value, memory);
        return keepGoing;
      };
      break;
    case 'orr':
      value = function(memory) {
        memory[getValue(to.value, memory)] |= getValue(aux.value, memory);
        return keepGoing;
      };
      break;
    case 'xor':
      value = function(memory) {
        memory[getValue(to.value, memory)] ^= getValue(aux.value, memory);
        return keepGoing;
      };
      break;
    case 'not':
      value = function(memory) {
        memory[getValue(to.value, memory)] = ~getValue(aux.value, memory);
        return keepGoing;
      };
      break;
    case 'shl':
      value = function(memory) {
        memory[getValue(to.value, memory)] <<= getValue(aux.value, memory);
        return keepGoing;
      };
      break;
    case 'shr':
      value = function(memory) {
        memory[getValue(to.value, memory)] >>= getValue(aux.value, memory);
        return keepGoing;
      };
      break;
    case 'prt':
      value = function(memory) {
        fds[getValue(to.value, memory)](getValue(aux.value, memory));
        return keepGoing;
      };
      break;
    case 'get':
      value = function(memory) {
        memory[getValue(to.value, memory)] = fds[getValue(aux.value, memory)]();
        return keepGoing;
      };
      break;
    default:
      throw new VMError('Invalid Instruction');
  }
  return {value: value, newOffset: newOffset};
}

/**
 * @param {!ArrayBuffer} buffer
 * @param {!Object} counters
 * @return {*}
 */
function execute(buffer, counters) {
  var memory = Array.from(new Uint32Array(buffer));
  var codeOffset = memory[0] / 4;
  var dataBuffer = buffer.slice(4, memory[0]);
  var cursor;
  try {
    for (var dataOffset = 1; dataOffset < codeOffset; dataOffset++) {
      counters['variables']++;
      cursor = consumeValue(dataBuffer);
      dataBuffer = dataBuffer.slice(cursor.newOffset);
      memory[dataOffset] = cursor.value;
    }
  } catch (e) {
  }
  try {
    var codeBuffer = buffer.slice(memory[0]);
    while (true) {
      counters['instructions']++;
      cursor = consumeInstruction(codeBuffer);
      if (!cursor.value) break;
      codeBuffer = codeBuffer.slice(cursor.newOffset);
      memory[codeOffset++] = cursor.value;
    }
  } catch (e) {
  }
  for (memory[codeOffset] = function() {
         return keepGoing;
       }; typeof memory[codeOffset - 1] === 'function'; codeOffset--) {
    memory[codeOffset - 1] = (function(currentFunction, oldFunction) {
      return function(memory) {
        counters['cycles']++;
        var ret = currentFunction(memory);
        if (ret === keepGoing) {
          return oldFunction(memory);
        }
        return ret;
      };
    })(memory[codeOffset - 1], memory[codeOffset]);
  }
  return memory[codeOffset](memory);
}
