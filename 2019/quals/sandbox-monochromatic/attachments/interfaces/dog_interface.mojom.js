// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

'use strict';

(function() {
  var mojomId = 'third_party/blink/public/mojom/CTF/dog_interface.mojom';
  if (mojo.internal.isMojomLoaded(mojomId)) {
    console.warn('The following mojom is loaded multiple times: ' + mojomId);
    return;
  }
  mojo.internal.markMojomLoaded(mojomId);
  var bindings = mojo;
  var associatedBindings = mojo;
  var codec = mojo.internal;
  var validator = mojo.internal;

  var exports = mojo.internal.exposeNamespace('blink.mojom');
  var origin$ =
      mojo.internal.exposeNamespace('url.mojom');
  if (mojo.config.autoLoadMojomDeps) {
    mojo.internal.loadMojomIfNecessary(
        'url/mojom/origin.mojom', '../../../../../url/mojom/origin.mojom.js');
  }
  var food_interface$ =
      mojo.internal.exposeNamespace('blink.mojom');
  if (mojo.config.autoLoadMojomDeps) {
    mojo.internal.loadMojomIfNecessary(
        'third_party/blink/public/mojom/CTF/food_interface.mojom', 'food_interface.mojom.js');
  }



  function DogInterface_GetName_Params(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  DogInterface_GetName_Params.prototype.initDefaults_ = function() {
  };
  DogInterface_GetName_Params.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  DogInterface_GetName_Params.generate = function(generator_) {
    var generated = new DogInterface_GetName_Params;
    return generated;
  };

  DogInterface_GetName_Params.prototype.mutate = function(mutator_) {
    return this;
  };
  DogInterface_GetName_Params.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  DogInterface_GetName_Params.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  DogInterface_GetName_Params.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  DogInterface_GetName_Params.validate = function(messageValidator, offset) {
    var err;
    err = messageValidator.validateStructHeader(offset, codec.kStructHeaderSize);
    if (err !== validator.validationError.NONE)
        return err;

    var kVersionSizes = [
      {version: 0, numBytes: 8}
    ];
    err = messageValidator.validateStructVersion(offset, kVersionSizes);
    if (err !== validator.validationError.NONE)
        return err;

    return validator.validationError.NONE;
  };

  DogInterface_GetName_Params.encodedSize = codec.kStructHeaderSize + 0;

  DogInterface_GetName_Params.decode = function(decoder) {
    var packed;
    var val = new DogInterface_GetName_Params();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    return val;
  };

  DogInterface_GetName_Params.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(DogInterface_GetName_Params.encodedSize);
    encoder.writeUint32(0);
  };
  function DogInterface_GetName_ResponseParams(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  DogInterface_GetName_ResponseParams.prototype.initDefaults_ = function() {
    this.name = null;
  };
  DogInterface_GetName_ResponseParams.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  DogInterface_GetName_ResponseParams.generate = function(generator_) {
    var generated = new DogInterface_GetName_ResponseParams;
    generated.name = generator_.generateString(false);
    return generated;
  };

  DogInterface_GetName_ResponseParams.prototype.mutate = function(mutator_) {
    if (mutator_.chooseMutateField()) {
      this.name = mutator_.mutateString(this.name, false);
    }
    return this;
  };
  DogInterface_GetName_ResponseParams.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  DogInterface_GetName_ResponseParams.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  DogInterface_GetName_ResponseParams.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  DogInterface_GetName_ResponseParams.validate = function(messageValidator, offset) {
    var err;
    err = messageValidator.validateStructHeader(offset, codec.kStructHeaderSize);
    if (err !== validator.validationError.NONE)
        return err;

    var kVersionSizes = [
      {version: 0, numBytes: 16}
    ];
    err = messageValidator.validateStructVersion(offset, kVersionSizes);
    if (err !== validator.validationError.NONE)
        return err;


    // validate DogInterface_GetName_ResponseParams.name
    err = messageValidator.validateStringPointer(offset + codec.kStructHeaderSize + 0, false)
    if (err !== validator.validationError.NONE)
        return err;

    return validator.validationError.NONE;
  };

  DogInterface_GetName_ResponseParams.encodedSize = codec.kStructHeaderSize + 8;

  DogInterface_GetName_ResponseParams.decode = function(decoder) {
    var packed;
    var val = new DogInterface_GetName_ResponseParams();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    val.name = decoder.decodeStruct(codec.String);
    return val;
  };

  DogInterface_GetName_ResponseParams.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(DogInterface_GetName_ResponseParams.encodedSize);
    encoder.writeUint32(0);
    encoder.encodeStruct(codec.String, val.name);
  };
  function DogInterface_SetName_Params(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  DogInterface_SetName_Params.prototype.initDefaults_ = function() {
    this.newName = null;
  };
  DogInterface_SetName_Params.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  DogInterface_SetName_Params.generate = function(generator_) {
    var generated = new DogInterface_SetName_Params;
    generated.newName = generator_.generateString(false);
    return generated;
  };

  DogInterface_SetName_Params.prototype.mutate = function(mutator_) {
    if (mutator_.chooseMutateField()) {
      this.newName = mutator_.mutateString(this.newName, false);
    }
    return this;
  };
  DogInterface_SetName_Params.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  DogInterface_SetName_Params.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  DogInterface_SetName_Params.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  DogInterface_SetName_Params.validate = function(messageValidator, offset) {
    var err;
    err = messageValidator.validateStructHeader(offset, codec.kStructHeaderSize);
    if (err !== validator.validationError.NONE)
        return err;

    var kVersionSizes = [
      {version: 0, numBytes: 16}
    ];
    err = messageValidator.validateStructVersion(offset, kVersionSizes);
    if (err !== validator.validationError.NONE)
        return err;


    // validate DogInterface_SetName_Params.newName
    err = messageValidator.validateStringPointer(offset + codec.kStructHeaderSize + 0, false)
    if (err !== validator.validationError.NONE)
        return err;

    return validator.validationError.NONE;
  };

  DogInterface_SetName_Params.encodedSize = codec.kStructHeaderSize + 8;

  DogInterface_SetName_Params.decode = function(decoder) {
    var packed;
    var val = new DogInterface_SetName_Params();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    val.newName = decoder.decodeStruct(codec.String);
    return val;
  };

  DogInterface_SetName_Params.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(DogInterface_SetName_Params.encodedSize);
    encoder.writeUint32(0);
    encoder.encodeStruct(codec.String, val.newName);
  };
  function DogInterface_SetName_ResponseParams(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  DogInterface_SetName_ResponseParams.prototype.initDefaults_ = function() {
  };
  DogInterface_SetName_ResponseParams.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  DogInterface_SetName_ResponseParams.generate = function(generator_) {
    var generated = new DogInterface_SetName_ResponseParams;
    return generated;
  };

  DogInterface_SetName_ResponseParams.prototype.mutate = function(mutator_) {
    return this;
  };
  DogInterface_SetName_ResponseParams.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  DogInterface_SetName_ResponseParams.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  DogInterface_SetName_ResponseParams.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  DogInterface_SetName_ResponseParams.validate = function(messageValidator, offset) {
    var err;
    err = messageValidator.validateStructHeader(offset, codec.kStructHeaderSize);
    if (err !== validator.validationError.NONE)
        return err;

    var kVersionSizes = [
      {version: 0, numBytes: 8}
    ];
    err = messageValidator.validateStructVersion(offset, kVersionSizes);
    if (err !== validator.validationError.NONE)
        return err;

    return validator.validationError.NONE;
  };

  DogInterface_SetName_ResponseParams.encodedSize = codec.kStructHeaderSize + 0;

  DogInterface_SetName_ResponseParams.decode = function(decoder) {
    var packed;
    var val = new DogInterface_SetName_ResponseParams();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    return val;
  };

  DogInterface_SetName_ResponseParams.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(DogInterface_SetName_ResponseParams.encodedSize);
    encoder.writeUint32(0);
  };
  function DogInterface_GetAge_Params(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  DogInterface_GetAge_Params.prototype.initDefaults_ = function() {
  };
  DogInterface_GetAge_Params.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  DogInterface_GetAge_Params.generate = function(generator_) {
    var generated = new DogInterface_GetAge_Params;
    return generated;
  };

  DogInterface_GetAge_Params.prototype.mutate = function(mutator_) {
    return this;
  };
  DogInterface_GetAge_Params.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  DogInterface_GetAge_Params.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  DogInterface_GetAge_Params.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  DogInterface_GetAge_Params.validate = function(messageValidator, offset) {
    var err;
    err = messageValidator.validateStructHeader(offset, codec.kStructHeaderSize);
    if (err !== validator.validationError.NONE)
        return err;

    var kVersionSizes = [
      {version: 0, numBytes: 8}
    ];
    err = messageValidator.validateStructVersion(offset, kVersionSizes);
    if (err !== validator.validationError.NONE)
        return err;

    return validator.validationError.NONE;
  };

  DogInterface_GetAge_Params.encodedSize = codec.kStructHeaderSize + 0;

  DogInterface_GetAge_Params.decode = function(decoder) {
    var packed;
    var val = new DogInterface_GetAge_Params();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    return val;
  };

  DogInterface_GetAge_Params.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(DogInterface_GetAge_Params.encodedSize);
    encoder.writeUint32(0);
  };
  function DogInterface_GetAge_ResponseParams(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  DogInterface_GetAge_ResponseParams.prototype.initDefaults_ = function() {
    this.age = 0;
  };
  DogInterface_GetAge_ResponseParams.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  DogInterface_GetAge_ResponseParams.generate = function(generator_) {
    var generated = new DogInterface_GetAge_ResponseParams;
    generated.age = generator_.generateUint64();
    return generated;
  };

  DogInterface_GetAge_ResponseParams.prototype.mutate = function(mutator_) {
    if (mutator_.chooseMutateField()) {
      this.age = mutator_.mutateUint64(this.age);
    }
    return this;
  };
  DogInterface_GetAge_ResponseParams.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  DogInterface_GetAge_ResponseParams.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  DogInterface_GetAge_ResponseParams.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  DogInterface_GetAge_ResponseParams.validate = function(messageValidator, offset) {
    var err;
    err = messageValidator.validateStructHeader(offset, codec.kStructHeaderSize);
    if (err !== validator.validationError.NONE)
        return err;

    var kVersionSizes = [
      {version: 0, numBytes: 16}
    ];
    err = messageValidator.validateStructVersion(offset, kVersionSizes);
    if (err !== validator.validationError.NONE)
        return err;


    return validator.validationError.NONE;
  };

  DogInterface_GetAge_ResponseParams.encodedSize = codec.kStructHeaderSize + 8;

  DogInterface_GetAge_ResponseParams.decode = function(decoder) {
    var packed;
    var val = new DogInterface_GetAge_ResponseParams();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    val.age = decoder.decodeStruct(codec.Uint64);
    return val;
  };

  DogInterface_GetAge_ResponseParams.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(DogInterface_GetAge_ResponseParams.encodedSize);
    encoder.writeUint32(0);
    encoder.encodeStruct(codec.Uint64, val.age);
  };
  function DogInterface_SetAge_Params(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  DogInterface_SetAge_Params.prototype.initDefaults_ = function() {
    this.newAge = 0;
  };
  DogInterface_SetAge_Params.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  DogInterface_SetAge_Params.generate = function(generator_) {
    var generated = new DogInterface_SetAge_Params;
    generated.newAge = generator_.generateUint64();
    return generated;
  };

  DogInterface_SetAge_Params.prototype.mutate = function(mutator_) {
    if (mutator_.chooseMutateField()) {
      this.newAge = mutator_.mutateUint64(this.newAge);
    }
    return this;
  };
  DogInterface_SetAge_Params.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  DogInterface_SetAge_Params.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  DogInterface_SetAge_Params.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  DogInterface_SetAge_Params.validate = function(messageValidator, offset) {
    var err;
    err = messageValidator.validateStructHeader(offset, codec.kStructHeaderSize);
    if (err !== validator.validationError.NONE)
        return err;

    var kVersionSizes = [
      {version: 0, numBytes: 16}
    ];
    err = messageValidator.validateStructVersion(offset, kVersionSizes);
    if (err !== validator.validationError.NONE)
        return err;


    return validator.validationError.NONE;
  };

  DogInterface_SetAge_Params.encodedSize = codec.kStructHeaderSize + 8;

  DogInterface_SetAge_Params.decode = function(decoder) {
    var packed;
    var val = new DogInterface_SetAge_Params();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    val.newAge = decoder.decodeStruct(codec.Uint64);
    return val;
  };

  DogInterface_SetAge_Params.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(DogInterface_SetAge_Params.encodedSize);
    encoder.writeUint32(0);
    encoder.encodeStruct(codec.Uint64, val.newAge);
  };
  function DogInterface_SetAge_ResponseParams(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  DogInterface_SetAge_ResponseParams.prototype.initDefaults_ = function() {
  };
  DogInterface_SetAge_ResponseParams.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  DogInterface_SetAge_ResponseParams.generate = function(generator_) {
    var generated = new DogInterface_SetAge_ResponseParams;
    return generated;
  };

  DogInterface_SetAge_ResponseParams.prototype.mutate = function(mutator_) {
    return this;
  };
  DogInterface_SetAge_ResponseParams.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  DogInterface_SetAge_ResponseParams.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  DogInterface_SetAge_ResponseParams.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  DogInterface_SetAge_ResponseParams.validate = function(messageValidator, offset) {
    var err;
    err = messageValidator.validateStructHeader(offset, codec.kStructHeaderSize);
    if (err !== validator.validationError.NONE)
        return err;

    var kVersionSizes = [
      {version: 0, numBytes: 8}
    ];
    err = messageValidator.validateStructVersion(offset, kVersionSizes);
    if (err !== validator.validationError.NONE)
        return err;

    return validator.validationError.NONE;
  };

  DogInterface_SetAge_ResponseParams.encodedSize = codec.kStructHeaderSize + 0;

  DogInterface_SetAge_ResponseParams.decode = function(decoder) {
    var packed;
    var val = new DogInterface_SetAge_ResponseParams();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    return val;
  };

  DogInterface_SetAge_ResponseParams.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(DogInterface_SetAge_ResponseParams.encodedSize);
    encoder.writeUint32(0);
  };
  function DogInterface_GetWeight_Params(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  DogInterface_GetWeight_Params.prototype.initDefaults_ = function() {
  };
  DogInterface_GetWeight_Params.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  DogInterface_GetWeight_Params.generate = function(generator_) {
    var generated = new DogInterface_GetWeight_Params;
    return generated;
  };

  DogInterface_GetWeight_Params.prototype.mutate = function(mutator_) {
    return this;
  };
  DogInterface_GetWeight_Params.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  DogInterface_GetWeight_Params.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  DogInterface_GetWeight_Params.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  DogInterface_GetWeight_Params.validate = function(messageValidator, offset) {
    var err;
    err = messageValidator.validateStructHeader(offset, codec.kStructHeaderSize);
    if (err !== validator.validationError.NONE)
        return err;

    var kVersionSizes = [
      {version: 0, numBytes: 8}
    ];
    err = messageValidator.validateStructVersion(offset, kVersionSizes);
    if (err !== validator.validationError.NONE)
        return err;

    return validator.validationError.NONE;
  };

  DogInterface_GetWeight_Params.encodedSize = codec.kStructHeaderSize + 0;

  DogInterface_GetWeight_Params.decode = function(decoder) {
    var packed;
    var val = new DogInterface_GetWeight_Params();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    return val;
  };

  DogInterface_GetWeight_Params.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(DogInterface_GetWeight_Params.encodedSize);
    encoder.writeUint32(0);
  };
  function DogInterface_GetWeight_ResponseParams(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  DogInterface_GetWeight_ResponseParams.prototype.initDefaults_ = function() {
    this.weight = 0;
  };
  DogInterface_GetWeight_ResponseParams.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  DogInterface_GetWeight_ResponseParams.generate = function(generator_) {
    var generated = new DogInterface_GetWeight_ResponseParams;
    generated.weight = generator_.generateUint64();
    return generated;
  };

  DogInterface_GetWeight_ResponseParams.prototype.mutate = function(mutator_) {
    if (mutator_.chooseMutateField()) {
      this.weight = mutator_.mutateUint64(this.weight);
    }
    return this;
  };
  DogInterface_GetWeight_ResponseParams.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  DogInterface_GetWeight_ResponseParams.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  DogInterface_GetWeight_ResponseParams.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  DogInterface_GetWeight_ResponseParams.validate = function(messageValidator, offset) {
    var err;
    err = messageValidator.validateStructHeader(offset, codec.kStructHeaderSize);
    if (err !== validator.validationError.NONE)
        return err;

    var kVersionSizes = [
      {version: 0, numBytes: 16}
    ];
    err = messageValidator.validateStructVersion(offset, kVersionSizes);
    if (err !== validator.validationError.NONE)
        return err;


    return validator.validationError.NONE;
  };

  DogInterface_GetWeight_ResponseParams.encodedSize = codec.kStructHeaderSize + 8;

  DogInterface_GetWeight_ResponseParams.decode = function(decoder) {
    var packed;
    var val = new DogInterface_GetWeight_ResponseParams();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    val.weight = decoder.decodeStruct(codec.Uint64);
    return val;
  };

  DogInterface_GetWeight_ResponseParams.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(DogInterface_GetWeight_ResponseParams.encodedSize);
    encoder.writeUint32(0);
    encoder.encodeStruct(codec.Uint64, val.weight);
  };
  function DogInterface_SetWeight_Params(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  DogInterface_SetWeight_Params.prototype.initDefaults_ = function() {
    this.newWeight = 0;
  };
  DogInterface_SetWeight_Params.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  DogInterface_SetWeight_Params.generate = function(generator_) {
    var generated = new DogInterface_SetWeight_Params;
    generated.newWeight = generator_.generateUint64();
    return generated;
  };

  DogInterface_SetWeight_Params.prototype.mutate = function(mutator_) {
    if (mutator_.chooseMutateField()) {
      this.newWeight = mutator_.mutateUint64(this.newWeight);
    }
    return this;
  };
  DogInterface_SetWeight_Params.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  DogInterface_SetWeight_Params.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  DogInterface_SetWeight_Params.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  DogInterface_SetWeight_Params.validate = function(messageValidator, offset) {
    var err;
    err = messageValidator.validateStructHeader(offset, codec.kStructHeaderSize);
    if (err !== validator.validationError.NONE)
        return err;

    var kVersionSizes = [
      {version: 0, numBytes: 16}
    ];
    err = messageValidator.validateStructVersion(offset, kVersionSizes);
    if (err !== validator.validationError.NONE)
        return err;


    return validator.validationError.NONE;
  };

  DogInterface_SetWeight_Params.encodedSize = codec.kStructHeaderSize + 8;

  DogInterface_SetWeight_Params.decode = function(decoder) {
    var packed;
    var val = new DogInterface_SetWeight_Params();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    val.newWeight = decoder.decodeStruct(codec.Uint64);
    return val;
  };

  DogInterface_SetWeight_Params.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(DogInterface_SetWeight_Params.encodedSize);
    encoder.writeUint32(0);
    encoder.encodeStruct(codec.Uint64, val.newWeight);
  };
  function DogInterface_SetWeight_ResponseParams(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  DogInterface_SetWeight_ResponseParams.prototype.initDefaults_ = function() {
  };
  DogInterface_SetWeight_ResponseParams.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  DogInterface_SetWeight_ResponseParams.generate = function(generator_) {
    var generated = new DogInterface_SetWeight_ResponseParams;
    return generated;
  };

  DogInterface_SetWeight_ResponseParams.prototype.mutate = function(mutator_) {
    return this;
  };
  DogInterface_SetWeight_ResponseParams.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  DogInterface_SetWeight_ResponseParams.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  DogInterface_SetWeight_ResponseParams.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  DogInterface_SetWeight_ResponseParams.validate = function(messageValidator, offset) {
    var err;
    err = messageValidator.validateStructHeader(offset, codec.kStructHeaderSize);
    if (err !== validator.validationError.NONE)
        return err;

    var kVersionSizes = [
      {version: 0, numBytes: 8}
    ];
    err = messageValidator.validateStructVersion(offset, kVersionSizes);
    if (err !== validator.validationError.NONE)
        return err;

    return validator.validationError.NONE;
  };

  DogInterface_SetWeight_ResponseParams.encodedSize = codec.kStructHeaderSize + 0;

  DogInterface_SetWeight_ResponseParams.decode = function(decoder) {
    var packed;
    var val = new DogInterface_SetWeight_ResponseParams();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    return val;
  };

  DogInterface_SetWeight_ResponseParams.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(DogInterface_SetWeight_ResponseParams.encodedSize);
    encoder.writeUint32(0);
  };
  function DogInterface_CookAndEat_Params(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  DogInterface_CookAndEat_Params.prototype.initDefaults_ = function() {
    this.food = new food_interface$.FoodInterfacePtr();
  };
  DogInterface_CookAndEat_Params.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  DogInterface_CookAndEat_Params.generate = function(generator_) {
    var generated = new DogInterface_CookAndEat_Params;
    generated.food = generator_.generateInterface("blink.mojom.FoodInterface", false);
    return generated;
  };

  DogInterface_CookAndEat_Params.prototype.mutate = function(mutator_) {
    if (mutator_.chooseMutateField()) {
      this.food = mutator_.mutateInterface(this.food, "blink.mojom.FoodInterface", false);
    }
    return this;
  };
  DogInterface_CookAndEat_Params.prototype.getHandleDeps = function() {
    var handles = [];
    if (this.food !== null) {
      Array.prototype.push.apply(handles, ["blink.mojom.FoodInterfacePtr"]);
    }
    return handles;
  };

  DogInterface_CookAndEat_Params.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  DogInterface_CookAndEat_Params.prototype.setHandlesInternal_ = function(handles, idx) {
    this.food = handles[idx++];;
    return idx;
  };

  DogInterface_CookAndEat_Params.validate = function(messageValidator, offset) {
    var err;
    err = messageValidator.validateStructHeader(offset, codec.kStructHeaderSize);
    if (err !== validator.validationError.NONE)
        return err;

    var kVersionSizes = [
      {version: 0, numBytes: 16}
    ];
    err = messageValidator.validateStructVersion(offset, kVersionSizes);
    if (err !== validator.validationError.NONE)
        return err;


    // validate DogInterface_CookAndEat_Params.food
    err = messageValidator.validateInterface(offset + codec.kStructHeaderSize + 0, false);
    if (err !== validator.validationError.NONE)
        return err;

    return validator.validationError.NONE;
  };

  DogInterface_CookAndEat_Params.encodedSize = codec.kStructHeaderSize + 8;

  DogInterface_CookAndEat_Params.decode = function(decoder) {
    var packed;
    var val = new DogInterface_CookAndEat_Params();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    val.food = decoder.decodeStruct(new codec.Interface(food_interface$.FoodInterfacePtr));
    return val;
  };

  DogInterface_CookAndEat_Params.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(DogInterface_CookAndEat_Params.encodedSize);
    encoder.writeUint32(0);
    encoder.encodeStruct(new codec.Interface(food_interface$.FoodInterfacePtr), val.food);
  };
  function DogInterface_CookAndEat_ResponseParams(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  DogInterface_CookAndEat_ResponseParams.prototype.initDefaults_ = function() {
  };
  DogInterface_CookAndEat_ResponseParams.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  DogInterface_CookAndEat_ResponseParams.generate = function(generator_) {
    var generated = new DogInterface_CookAndEat_ResponseParams;
    return generated;
  };

  DogInterface_CookAndEat_ResponseParams.prototype.mutate = function(mutator_) {
    return this;
  };
  DogInterface_CookAndEat_ResponseParams.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  DogInterface_CookAndEat_ResponseParams.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  DogInterface_CookAndEat_ResponseParams.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  DogInterface_CookAndEat_ResponseParams.validate = function(messageValidator, offset) {
    var err;
    err = messageValidator.validateStructHeader(offset, codec.kStructHeaderSize);
    if (err !== validator.validationError.NONE)
        return err;

    var kVersionSizes = [
      {version: 0, numBytes: 8}
    ];
    err = messageValidator.validateStructVersion(offset, kVersionSizes);
    if (err !== validator.validationError.NONE)
        return err;

    return validator.validationError.NONE;
  };

  DogInterface_CookAndEat_ResponseParams.encodedSize = codec.kStructHeaderSize + 0;

  DogInterface_CookAndEat_ResponseParams.decode = function(decoder) {
    var packed;
    var val = new DogInterface_CookAndEat_ResponseParams();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    return val;
  };

  DogInterface_CookAndEat_ResponseParams.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(DogInterface_CookAndEat_ResponseParams.encodedSize);
    encoder.writeUint32(0);
  };
  var kDogInterface_GetName_Name = 1608910662;
  var kDogInterface_SetName_Name = 1514294029;
  var kDogInterface_GetAge_Name = 2046110025;
  var kDogInterface_SetAge_Name = 614458722;
  var kDogInterface_GetWeight_Name = 1770375486;
  var kDogInterface_SetWeight_Name = 1754351392;
  var kDogInterface_CookAndEat_Name = 1611027585;

  function DogInterfacePtr(handleOrPtrInfo) {
    this.ptr = new bindings.InterfacePtrController(DogInterface,
                                                   handleOrPtrInfo);
  }

  function DogInterfaceAssociatedPtr(associatedInterfacePtrInfo) {
    this.ptr = new associatedBindings.AssociatedInterfacePtrController(
        DogInterface, associatedInterfacePtrInfo);
  }

  DogInterfaceAssociatedPtr.prototype =
      Object.create(DogInterfacePtr.prototype);
  DogInterfaceAssociatedPtr.prototype.constructor =
      DogInterfaceAssociatedPtr;

  function DogInterfaceProxy(receiver) {
    this.receiver_ = receiver;
  }
  DogInterfacePtr.prototype.getName = function() {
    return DogInterfaceProxy.prototype.getName
        .apply(this.ptr.getProxy(), arguments);
  };

  DogInterfaceProxy.prototype.getName = function() {
    var params_ = new DogInterface_GetName_Params();
    return new Promise(function(resolve, reject) {
      var builder = new codec.MessageV1Builder(
          kDogInterface_GetName_Name,
          codec.align(DogInterface_GetName_Params.encodedSize),
          codec.kMessageExpectsResponse, 0);
      builder.encodeStruct(DogInterface_GetName_Params, params_);
      var message = builder.finish();
      this.receiver_.acceptAndExpectResponse(message).then(function(message) {
        var reader = new codec.MessageReader(message);
        var responseParams =
            reader.decodeStruct(DogInterface_GetName_ResponseParams);
        resolve(responseParams);
      }).catch(function(result) {
        reject(Error("Connection error: " + result));
      });
    }.bind(this));
  };
  DogInterfacePtr.prototype.setName = function() {
    return DogInterfaceProxy.prototype.setName
        .apply(this.ptr.getProxy(), arguments);
  };

  DogInterfaceProxy.prototype.setName = function(newName) {
    var params_ = new DogInterface_SetName_Params();
    params_.newName = newName;
    return new Promise(function(resolve, reject) {
      var builder = new codec.MessageV1Builder(
          kDogInterface_SetName_Name,
          codec.align(DogInterface_SetName_Params.encodedSize),
          codec.kMessageExpectsResponse, 0);
      builder.encodeStruct(DogInterface_SetName_Params, params_);
      var message = builder.finish();
      this.receiver_.acceptAndExpectResponse(message).then(function(message) {
        var reader = new codec.MessageReader(message);
        var responseParams =
            reader.decodeStruct(DogInterface_SetName_ResponseParams);
        resolve(responseParams);
      }).catch(function(result) {
        reject(Error("Connection error: " + result));
      });
    }.bind(this));
  };
  DogInterfacePtr.prototype.getAge = function() {
    return DogInterfaceProxy.prototype.getAge
        .apply(this.ptr.getProxy(), arguments);
  };

  DogInterfaceProxy.prototype.getAge = function() {
    var params_ = new DogInterface_GetAge_Params();
    return new Promise(function(resolve, reject) {
      var builder = new codec.MessageV1Builder(
          kDogInterface_GetAge_Name,
          codec.align(DogInterface_GetAge_Params.encodedSize),
          codec.kMessageExpectsResponse, 0);
      builder.encodeStruct(DogInterface_GetAge_Params, params_);
      var message = builder.finish();
      this.receiver_.acceptAndExpectResponse(message).then(function(message) {
        var reader = new codec.MessageReader(message);
        var responseParams =
            reader.decodeStruct(DogInterface_GetAge_ResponseParams);
        resolve(responseParams);
      }).catch(function(result) {
        reject(Error("Connection error: " + result));
      });
    }.bind(this));
  };
  DogInterfacePtr.prototype.setAge = function() {
    return DogInterfaceProxy.prototype.setAge
        .apply(this.ptr.getProxy(), arguments);
  };

  DogInterfaceProxy.prototype.setAge = function(newAge) {
    var params_ = new DogInterface_SetAge_Params();
    params_.newAge = newAge;
    return new Promise(function(resolve, reject) {
      var builder = new codec.MessageV1Builder(
          kDogInterface_SetAge_Name,
          codec.align(DogInterface_SetAge_Params.encodedSize),
          codec.kMessageExpectsResponse, 0);
      builder.encodeStruct(DogInterface_SetAge_Params, params_);
      var message = builder.finish();
      this.receiver_.acceptAndExpectResponse(message).then(function(message) {
        var reader = new codec.MessageReader(message);
        var responseParams =
            reader.decodeStruct(DogInterface_SetAge_ResponseParams);
        resolve(responseParams);
      }).catch(function(result) {
        reject(Error("Connection error: " + result));
      });
    }.bind(this));
  };
  DogInterfacePtr.prototype.getWeight = function() {
    return DogInterfaceProxy.prototype.getWeight
        .apply(this.ptr.getProxy(), arguments);
  };

  DogInterfaceProxy.prototype.getWeight = function() {
    var params_ = new DogInterface_GetWeight_Params();
    return new Promise(function(resolve, reject) {
      var builder = new codec.MessageV1Builder(
          kDogInterface_GetWeight_Name,
          codec.align(DogInterface_GetWeight_Params.encodedSize),
          codec.kMessageExpectsResponse, 0);
      builder.encodeStruct(DogInterface_GetWeight_Params, params_);
      var message = builder.finish();
      this.receiver_.acceptAndExpectResponse(message).then(function(message) {
        var reader = new codec.MessageReader(message);
        var responseParams =
            reader.decodeStruct(DogInterface_GetWeight_ResponseParams);
        resolve(responseParams);
      }).catch(function(result) {
        reject(Error("Connection error: " + result));
      });
    }.bind(this));
  };
  DogInterfacePtr.prototype.setWeight = function() {
    return DogInterfaceProxy.prototype.setWeight
        .apply(this.ptr.getProxy(), arguments);
  };

  DogInterfaceProxy.prototype.setWeight = function(newWeight) {
    var params_ = new DogInterface_SetWeight_Params();
    params_.newWeight = newWeight;
    return new Promise(function(resolve, reject) {
      var builder = new codec.MessageV1Builder(
          kDogInterface_SetWeight_Name,
          codec.align(DogInterface_SetWeight_Params.encodedSize),
          codec.kMessageExpectsResponse, 0);
      builder.encodeStruct(DogInterface_SetWeight_Params, params_);
      var message = builder.finish();
      this.receiver_.acceptAndExpectResponse(message).then(function(message) {
        var reader = new codec.MessageReader(message);
        var responseParams =
            reader.decodeStruct(DogInterface_SetWeight_ResponseParams);
        resolve(responseParams);
      }).catch(function(result) {
        reject(Error("Connection error: " + result));
      });
    }.bind(this));
  };
  DogInterfacePtr.prototype.cookAndEat = function() {
    return DogInterfaceProxy.prototype.cookAndEat
        .apply(this.ptr.getProxy(), arguments);
  };

  DogInterfaceProxy.prototype.cookAndEat = function(food) {
    var params_ = new DogInterface_CookAndEat_Params();
    params_.food = food;
    return new Promise(function(resolve, reject) {
      var builder = new codec.MessageV1Builder(
          kDogInterface_CookAndEat_Name,
          codec.align(DogInterface_CookAndEat_Params.encodedSize),
          codec.kMessageExpectsResponse, 0);
      builder.encodeStruct(DogInterface_CookAndEat_Params, params_);
      var message = builder.finish();
      this.receiver_.acceptAndExpectResponse(message).then(function(message) {
        var reader = new codec.MessageReader(message);
        var responseParams =
            reader.decodeStruct(DogInterface_CookAndEat_ResponseParams);
        resolve(responseParams);
      }).catch(function(result) {
        reject(Error("Connection error: " + result));
      });
    }.bind(this));
  };

  function DogInterfaceStub(delegate) {
    this.delegate_ = delegate;
  }
  DogInterfaceStub.prototype.getName = function() {
    return this.delegate_ && this.delegate_.getName && this.delegate_.getName();
  }
  DogInterfaceStub.prototype.setName = function(newName) {
    return this.delegate_ && this.delegate_.setName && this.delegate_.setName(newName);
  }
  DogInterfaceStub.prototype.getAge = function() {
    return this.delegate_ && this.delegate_.getAge && this.delegate_.getAge();
  }
  DogInterfaceStub.prototype.setAge = function(newAge) {
    return this.delegate_ && this.delegate_.setAge && this.delegate_.setAge(newAge);
  }
  DogInterfaceStub.prototype.getWeight = function() {
    return this.delegate_ && this.delegate_.getWeight && this.delegate_.getWeight();
  }
  DogInterfaceStub.prototype.setWeight = function(newWeight) {
    return this.delegate_ && this.delegate_.setWeight && this.delegate_.setWeight(newWeight);
  }
  DogInterfaceStub.prototype.cookAndEat = function(food) {
    return this.delegate_ && this.delegate_.cookAndEat && this.delegate_.cookAndEat(food);
  }

  DogInterfaceStub.prototype.accept = function(message) {
    var reader = new codec.MessageReader(message);
    switch (reader.messageName) {
    default:
      return false;
    }
  };

  DogInterfaceStub.prototype.acceptWithResponder =
      function(message, responder) {
    var reader = new codec.MessageReader(message);
    switch (reader.messageName) {
    case kDogInterface_GetName_Name:
      var params = reader.decodeStruct(DogInterface_GetName_Params);
      this.getName().then(function(response) {
        var responseParams =
            new DogInterface_GetName_ResponseParams();
        responseParams.name = response.name;
        var builder = new codec.MessageV1Builder(
            kDogInterface_GetName_Name,
            codec.align(DogInterface_GetName_ResponseParams.encodedSize),
            codec.kMessageIsResponse, reader.requestID);
        builder.encodeStruct(DogInterface_GetName_ResponseParams,
                             responseParams);
        var message = builder.finish();
        responder.accept(message);
      });
      return true;
    case kDogInterface_SetName_Name:
      var params = reader.decodeStruct(DogInterface_SetName_Params);
      this.setName(params.newName).then(function(response) {
        var responseParams =
            new DogInterface_SetName_ResponseParams();
        var builder = new codec.MessageV1Builder(
            kDogInterface_SetName_Name,
            codec.align(DogInterface_SetName_ResponseParams.encodedSize),
            codec.kMessageIsResponse, reader.requestID);
        builder.encodeStruct(DogInterface_SetName_ResponseParams,
                             responseParams);
        var message = builder.finish();
        responder.accept(message);
      });
      return true;
    case kDogInterface_GetAge_Name:
      var params = reader.decodeStruct(DogInterface_GetAge_Params);
      this.getAge().then(function(response) {
        var responseParams =
            new DogInterface_GetAge_ResponseParams();
        responseParams.age = response.age;
        var builder = new codec.MessageV1Builder(
            kDogInterface_GetAge_Name,
            codec.align(DogInterface_GetAge_ResponseParams.encodedSize),
            codec.kMessageIsResponse, reader.requestID);
        builder.encodeStruct(DogInterface_GetAge_ResponseParams,
                             responseParams);
        var message = builder.finish();
        responder.accept(message);
      });
      return true;
    case kDogInterface_SetAge_Name:
      var params = reader.decodeStruct(DogInterface_SetAge_Params);
      this.setAge(params.newAge).then(function(response) {
        var responseParams =
            new DogInterface_SetAge_ResponseParams();
        var builder = new codec.MessageV1Builder(
            kDogInterface_SetAge_Name,
            codec.align(DogInterface_SetAge_ResponseParams.encodedSize),
            codec.kMessageIsResponse, reader.requestID);
        builder.encodeStruct(DogInterface_SetAge_ResponseParams,
                             responseParams);
        var message = builder.finish();
        responder.accept(message);
      });
      return true;
    case kDogInterface_GetWeight_Name:
      var params = reader.decodeStruct(DogInterface_GetWeight_Params);
      this.getWeight().then(function(response) {
        var responseParams =
            new DogInterface_GetWeight_ResponseParams();
        responseParams.weight = response.weight;
        var builder = new codec.MessageV1Builder(
            kDogInterface_GetWeight_Name,
            codec.align(DogInterface_GetWeight_ResponseParams.encodedSize),
            codec.kMessageIsResponse, reader.requestID);
        builder.encodeStruct(DogInterface_GetWeight_ResponseParams,
                             responseParams);
        var message = builder.finish();
        responder.accept(message);
      });
      return true;
    case kDogInterface_SetWeight_Name:
      var params = reader.decodeStruct(DogInterface_SetWeight_Params);
      this.setWeight(params.newWeight).then(function(response) {
        var responseParams =
            new DogInterface_SetWeight_ResponseParams();
        var builder = new codec.MessageV1Builder(
            kDogInterface_SetWeight_Name,
            codec.align(DogInterface_SetWeight_ResponseParams.encodedSize),
            codec.kMessageIsResponse, reader.requestID);
        builder.encodeStruct(DogInterface_SetWeight_ResponseParams,
                             responseParams);
        var message = builder.finish();
        responder.accept(message);
      });
      return true;
    case kDogInterface_CookAndEat_Name:
      var params = reader.decodeStruct(DogInterface_CookAndEat_Params);
      this.cookAndEat(params.food).then(function(response) {
        var responseParams =
            new DogInterface_CookAndEat_ResponseParams();
        var builder = new codec.MessageV1Builder(
            kDogInterface_CookAndEat_Name,
            codec.align(DogInterface_CookAndEat_ResponseParams.encodedSize),
            codec.kMessageIsResponse, reader.requestID);
        builder.encodeStruct(DogInterface_CookAndEat_ResponseParams,
                             responseParams);
        var message = builder.finish();
        responder.accept(message);
      });
      return true;
    default:
      return false;
    }
  };

  function validateDogInterfaceRequest(messageValidator) {
    var message = messageValidator.message;
    var paramsClass = null;
    switch (message.getName()) {
      case kDogInterface_GetName_Name:
        if (message.expectsResponse())
          paramsClass = DogInterface_GetName_Params;
      break;
      case kDogInterface_SetName_Name:
        if (message.expectsResponse())
          paramsClass = DogInterface_SetName_Params;
      break;
      case kDogInterface_GetAge_Name:
        if (message.expectsResponse())
          paramsClass = DogInterface_GetAge_Params;
      break;
      case kDogInterface_SetAge_Name:
        if (message.expectsResponse())
          paramsClass = DogInterface_SetAge_Params;
      break;
      case kDogInterface_GetWeight_Name:
        if (message.expectsResponse())
          paramsClass = DogInterface_GetWeight_Params;
      break;
      case kDogInterface_SetWeight_Name:
        if (message.expectsResponse())
          paramsClass = DogInterface_SetWeight_Params;
      break;
      case kDogInterface_CookAndEat_Name:
        if (message.expectsResponse())
          paramsClass = DogInterface_CookAndEat_Params;
      break;
    }
    if (paramsClass === null)
      return validator.validationError.NONE;
    return paramsClass.validate(messageValidator, messageValidator.message.getHeaderNumBytes());
  }

  function validateDogInterfaceResponse(messageValidator) {
   var message = messageValidator.message;
   var paramsClass = null;
   switch (message.getName()) {
      case kDogInterface_GetName_Name:
        if (message.isResponse())
          paramsClass = DogInterface_GetName_ResponseParams;
        break;
      case kDogInterface_SetName_Name:
        if (message.isResponse())
          paramsClass = DogInterface_SetName_ResponseParams;
        break;
      case kDogInterface_GetAge_Name:
        if (message.isResponse())
          paramsClass = DogInterface_GetAge_ResponseParams;
        break;
      case kDogInterface_SetAge_Name:
        if (message.isResponse())
          paramsClass = DogInterface_SetAge_ResponseParams;
        break;
      case kDogInterface_GetWeight_Name:
        if (message.isResponse())
          paramsClass = DogInterface_GetWeight_ResponseParams;
        break;
      case kDogInterface_SetWeight_Name:
        if (message.isResponse())
          paramsClass = DogInterface_SetWeight_ResponseParams;
        break;
      case kDogInterface_CookAndEat_Name:
        if (message.isResponse())
          paramsClass = DogInterface_CookAndEat_ResponseParams;
        break;
    }
    if (paramsClass === null)
      return validator.validationError.NONE;
    return paramsClass.validate(messageValidator, messageValidator.message.getHeaderNumBytes());
  }

  var DogInterface = {
    name: 'blink.mojom.DogInterface',
    kVersion: 0,
    ptrClass: DogInterfacePtr,
    proxyClass: DogInterfaceProxy,
    stubClass: DogInterfaceStub,
    validateRequest: validateDogInterfaceRequest,
    validateResponse: validateDogInterfaceResponse,
    mojomId: 'third_party/blink/public/mojom/CTF/dog_interface.mojom',
    fuzzMethods: {
      getName: {
        params: DogInterface_GetName_Params,
      },
      setName: {
        params: DogInterface_SetName_Params,
      },
      getAge: {
        params: DogInterface_GetAge_Params,
      },
      setAge: {
        params: DogInterface_SetAge_Params,
      },
      getWeight: {
        params: DogInterface_GetWeight_Params,
      },
      setWeight: {
        params: DogInterface_SetWeight_Params,
      },
      cookAndEat: {
        params: DogInterface_CookAndEat_Params,
      },
    },
  };
  DogInterfaceStub.prototype.validator = validateDogInterfaceRequest;
  DogInterfaceProxy.prototype.validator = validateDogInterfaceResponse;
  exports.DogInterface = DogInterface;
  exports.DogInterfacePtr = DogInterfacePtr;
  exports.DogInterfaceAssociatedPtr = DogInterfaceAssociatedPtr;
})();