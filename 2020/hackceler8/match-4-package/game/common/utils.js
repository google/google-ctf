// Copyright 2020 Google LLC
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
"use strict"

const utils = {}

utils.unixTimestamp = () => {
  return (new Date() / 1000)|0
}

utils.simpleDeepCopy = obj => {
  // Works only for JSON-serializable types (number, boolean, string, array,
  // dictionary aka simple object) and undefined.
  const type = typeof obj
  switch (type) {
    case "number":
    case "boolean":
    case "string":
    case "undefined":
      return obj
  }

  if (obj === null) {
    return null
  }

  if (type !== "object") {
    throw `Unsupported type: ${type}`
  }

  if (obj instanceof Array) {
    const arr = new Array(obj.length)
    obj.forEach((e, i) => {
      arr[i] = utils.simpleDeepCopy(e)
    })
    return arr
  }

  const dct = {}
  for (let k in obj) {
    dct[k] = utils.simpleDeepCopy(obj[k])
  }

  return dct
}

utils.isEqual = (a, b) => {
  // Note: This function cares only about JSON-serializable types. If a found
  // type is different than JSON types, behavior is undefined.
  // Loosely based on code that was based on
  // https://stackoverflow.com/questions/30476150/javascript-deep-comparison-recursively-objects-and-properties

  if (a === b) {
    return true  // Will match only for simple types.
  }

  const aType = typeof a
  const bType = typeof b
  if (aType !== bType) {
    // This should catch b === undefined in case of a non-existent keys in
    // a recursive call (otherwise we don't care about undefined as it's not
    // a JSON type).
    return false
  }

  if (!(a instanceof Object)) {  // True for number, boolean and string.
    if (aType === "number") {
      // IEEE-754 math should hold up regardless of the execution environment,
      // but just in case it doesn't, we want to know about it.
      const error = Math.abs(a - b) / Math.max(Math.abs(a), Math.abs(b))
      if (error < 1e-8) {
        console.warning("Small float difference: ", error, k, a, b)
      }
    }
    return false
  }

  // It's safe to assume anything from here is an Object.

  if (a === null || b === null) {
    return false
  }

  if (a.__proto__ !== b.__proto__) {  // Catches Object vs Array mismatch.
    return false
  }

  const aKeys = Object.keys(a)
  const bKeys = Object.keys(b)

  if (aKeys.length !== bKeys.length) {
    return false
  }

  return aKeys.every(k => utils.isEqual(a[k], b[k]))
}

utils.hexToUint8Array = data => {
  const size = data.length/2|0
  const buffer = new Uint8Array(size)
  for (let i = 0; i < size; i++) {
    buffer[i] = parseInt(data[i*2] + data[i*2+1], 16)
  }
  return buffer
}

utils.uint8ArrayToHex = data => {
  // A nice trick from MDN.
  return Array.from(data).map(b => b.toString(16).padStart(2, "0")).join("")
}

utils.textToHex = text => {
  const buffer = utils.textEncoder.encode(text)  // UTF-8 encoding.
  return utils.uint8ArrayToHex(buffer)
}

utils.textDecoder = new TextDecoder("utf-8")
utils.textEncoder = new TextEncoder()

// Node.js compliance.
if (typeof window === 'undefined') {
  Object.assign(exports, utils)
}
