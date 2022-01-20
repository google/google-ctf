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
"use strict"

function unsafePropetyName(name) {
  return name === '__proto__' || name === 'prototype' || name === 'constructor'
}

const utils = {}

utils.isNonNullObject = obj => {
  return (typeof obj === 'object') && !Array.isArray(obj) && (obj !== null)
}

utils.objectHasOwnProperty = (obj, name) => {
  return Object.prototype.hasOwnProperty.call(obj, name)
}


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

  if (Array.isArray(obj)) {
    const arr = new Array(obj.length)
    obj.forEach((e, i) => {
      arr[i] = utils.simpleDeepCopy(e)
    })
    return arr
  }

  const dct = {}
  for (let k in obj) {
    if (!utils.objectHasOwnProperty(obj, k) || unsafePropetyName(k)) {
      continue
    }

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

  // a === b doesn't work with NaNs.
  if (Number.isNaN(a) && Number.isNaN(b)) {
    return true
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
        console.warning("Small float difference: ", error, a, b)
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

utils.initDeterministicRandomState = seed_str => {
  var h = 1779033703 ^ seed_str.length
  var i = 0
  for(; i < seed_str.length; i++) {
        h = Math.imul(h ^ seed_str.charCodeAt(i), 3432918353)
        h = h << 13 | h >>> 19
  }
  return [h]
}

utils.deterministicRandom = a_list => {
  var t = a_list[0] += 0x6D2B79F5
  t = Math.imul(t ^ t >>> 15, t | 1)
  t ^= t + Math.imul(t ^ t >>> 7, t | 61)
  return ((t ^ t >>> 14) >>> 0)
}

// mergeObjects merges the enumerable properties of source onto target recursively.
// Target and source must both be JSON-serializable objects (no cycles allowed or
// this will recurse infinitely).
utils.mergeObjects = (target, source) => {
  if (typeof target !== 'object' || typeof source !== 'object') {
    console.warn('utils.mergeObjects called with non-objects')
    return
  }

  if (!target || !source) {
    console.warn('utils.mergeObjects called with null')
    return
  }

  // This should work for both objects and arrays because an array's
  // enumerable properties are the indices of its elements.
  for (const key in source) {
    // Ignore inherited properties.
    if (!utils.objectHasOwnProperty(source, key) || unsafePropetyName(key)) {
      continue
    }

    if (typeof source[key] === 'object' && source[key] !== null) {
      // Object or array, merge recursively.
      if (!target[key]) {
        if (Array.isArray(source[key])) {
          target[key] = []
        } else {
          target[key] = {}
        }
      }
      utils.mergeObjects(target[key], source[key])
    } else {
      // Scalar (string, number, boolean, null), just copy the new value.
      target[key] = source[key]
    }
  }
}

// computeDiff computes the difference between newObject and oldObject, which
// must both be JSON-serializable objects. It returns a JSON-serializable object
// that contains two properties: mod and del. mod only contains the properties
// that were added to newObject or that changed. del contains true for every
// property that exists in oldObject but not in newObject.
utils.computeDiff = (newObject, oldObject) => {
  if (typeof newObject !== 'object' || typeof oldObject !== 'object') {
    console.warn('utils.computeDiff called with non-objects')
    return {mod: {}, del: {}}
  }

  if (!newObject || !oldObject) {
    console.warn('utils.computeDiff called with null')
    return {mod: {}, del: {}}
  }

  // modified are the values that were modified in this object.
  const modified = {}
  // deleted are the keys that exist in newObject but not in oldObject.
  const deleted = {}

  for (const key in newObject) {
    // Ignore inherited properties.
    if (!utils.objectHasOwnProperty(newObject, key) || unsafePropetyName(key)) {
      continue
    }

    if (!utils.objectHasOwnProperty(oldObject, key)) {
      // Something that didn't exist before.
      modified[key] = newObject[key]
    } else if (newObject[key] === null || typeof newObject[key] !== 'object') {
      if (oldObject[key] !== newObject[key]) {
        // A scalar value (string, null, number, boolean) that is different from before.
        modified[key] = newObject[key]
      }
    } else {
      // An object or array that exists in both.
      const {mod, del} = utils.computeDiff(newObject[key], oldObject[key])

      // Only add these to modified and deleted if they contain something.
      if (Object.keys(mod).length !== 0) {
        modified[key] = mod
      }

      if (Object.keys(del).length !== 0) {
        deleted[key] = del
      }
    }
  }

  for (const key in oldObject) {
    if (!utils.objectHasOwnProperty(oldObject, key) || unsafePropetyName(key)) {
      continue
    }

    if (!utils.objectHasOwnProperty(newObject, key)) {
      deleted[key] = true
    }
  }

  return {
    mod: modified,
    del: deleted,
  }
}

// deleteKeys deletes all the keys contained in keys from obj, recursively.
// obj and keys must both be JSON-serializable objects.
utils.deleteKeys = (obj, keys) => {
  if (typeof obj !== 'object' || typeof keys !== 'object') {
    console.warn('utils.deleteKeys called with non-objects')
    return
  }

  if (!obj || !keys) {
    console.warn('utils.deleteKeys called with null')
    return
  }

  for (const key in keys) {
    // Ignore inherited properties.
    if (!utils.objectHasOwnProperty(keys, key) || !utils.objectHasOwnProperty(obj, key) || unsafePropetyName(key)) {
      continue
    }

    if (typeof keys[key] !== 'object') {
      delete obj[key]
    } else {
      // Object or array, recurse
      utils.deleteKeys(obj[key], keys[key]);
    }
  }
}

utils.serverRandom = (target_tick) => {
  if (typeof globals === 'undefined') {
    // Server
    return ["__SENTINEL__"]
  }
  return main.serverRandom(target_tick)
}

utils.finalServerRandom = (tick, sentinel, backendObjects, consumedRngIds) => {
  try {
    if (typeof globals === 'undefined') {
      // Server
      // On servers, consumedRngIds and gameService will be non-null. Return the corresponding value in order.
      if (consumedRngIds.length === 0) {
        return null  // Happens if the client was disconnected with an RNG pending.
      }
      const ret = backendObjects.RNG.consumeRandom(tick, consumedRngIds[0])
      consumedRngIds.shift()
      return ret
    }
    return main.finalServerRandom(tick, sentinel)
  } catch (err) {
    console.log("Missing RNG value. ")
  }
}

// Node.js compliance.
if (typeof window === 'undefined') {
  Object.assign(exports, utils)
}
