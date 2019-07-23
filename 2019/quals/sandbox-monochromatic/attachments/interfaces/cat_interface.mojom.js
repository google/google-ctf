// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

'use strict';

(function() {
  var mojomId = 'third_party/blink/public/mojom/CTF/cat_interface.mojom';
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



  function CatInterface_GetName_Params(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  CatInterface_GetName_Params.prototype.initDefaults_ = function() {
  };
  CatInterface_GetName_Params.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  CatInterface_GetName_Params.generate = function(generator_) {
    var generated = new CatInterface_GetName_Params;
    return generated;
  };

  CatInterface_GetName_Params.prototype.mutate = function(mutator_) {
    return this;
  };
  CatInterface_GetName_Params.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  CatInterface_GetName_Params.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  CatInterface_GetName_Params.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  CatInterface_GetName_Params.validate = function(messageValidator, offset) {
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

  CatInterface_GetName_Params.encodedSize = codec.kStructHeaderSize + 0;

  CatInterface_GetName_Params.decode = function(decoder) {
    var packed;
    var val = new CatInterface_GetName_Params();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    return val;
  };

  CatInterface_GetName_Params.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(CatInterface_GetName_Params.encodedSize);
    encoder.writeUint32(0);
  };
  function CatInterface_GetName_ResponseParams(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  CatInterface_GetName_ResponseParams.prototype.initDefaults_ = function() {
    this.name = null;
  };
  CatInterface_GetName_ResponseParams.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  CatInterface_GetName_ResponseParams.generate = function(generator_) {
    var generated = new CatInterface_GetName_ResponseParams;
    generated.name = generator_.generateString(false);
    return generated;
  };

  CatInterface_GetName_ResponseParams.prototype.mutate = function(mutator_) {
    if (mutator_.chooseMutateField()) {
      this.name = mutator_.mutateString(this.name, false);
    }
    return this;
  };
  CatInterface_GetName_ResponseParams.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  CatInterface_GetName_ResponseParams.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  CatInterface_GetName_ResponseParams.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  CatInterface_GetName_ResponseParams.validate = function(messageValidator, offset) {
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


    // validate CatInterface_GetName_ResponseParams.name
    err = messageValidator.validateStringPointer(offset + codec.kStructHeaderSize + 0, false)
    if (err !== validator.validationError.NONE)
        return err;

    return validator.validationError.NONE;
  };

  CatInterface_GetName_ResponseParams.encodedSize = codec.kStructHeaderSize + 8;

  CatInterface_GetName_ResponseParams.decode = function(decoder) {
    var packed;
    var val = new CatInterface_GetName_ResponseParams();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    val.name = decoder.decodeStruct(codec.String);
    return val;
  };

  CatInterface_GetName_ResponseParams.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(CatInterface_GetName_ResponseParams.encodedSize);
    encoder.writeUint32(0);
    encoder.encodeStruct(codec.String, val.name);
  };
  function CatInterface_SetName_Params(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  CatInterface_SetName_Params.prototype.initDefaults_ = function() {
    this.newName = null;
  };
  CatInterface_SetName_Params.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  CatInterface_SetName_Params.generate = function(generator_) {
    var generated = new CatInterface_SetName_Params;
    generated.newName = generator_.generateString(false);
    return generated;
  };

  CatInterface_SetName_Params.prototype.mutate = function(mutator_) {
    if (mutator_.chooseMutateField()) {
      this.newName = mutator_.mutateString(this.newName, false);
    }
    return this;
  };
  CatInterface_SetName_Params.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  CatInterface_SetName_Params.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  CatInterface_SetName_Params.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  CatInterface_SetName_Params.validate = function(messageValidator, offset) {
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


    // validate CatInterface_SetName_Params.newName
    err = messageValidator.validateStringPointer(offset + codec.kStructHeaderSize + 0, false)
    if (err !== validator.validationError.NONE)
        return err;

    return validator.validationError.NONE;
  };

  CatInterface_SetName_Params.encodedSize = codec.kStructHeaderSize + 8;

  CatInterface_SetName_Params.decode = function(decoder) {
    var packed;
    var val = new CatInterface_SetName_Params();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    val.newName = decoder.decodeStruct(codec.String);
    return val;
  };

  CatInterface_SetName_Params.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(CatInterface_SetName_Params.encodedSize);
    encoder.writeUint32(0);
    encoder.encodeStruct(codec.String, val.newName);
  };
  function CatInterface_SetName_ResponseParams(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  CatInterface_SetName_ResponseParams.prototype.initDefaults_ = function() {
  };
  CatInterface_SetName_ResponseParams.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  CatInterface_SetName_ResponseParams.generate = function(generator_) {
    var generated = new CatInterface_SetName_ResponseParams;
    return generated;
  };

  CatInterface_SetName_ResponseParams.prototype.mutate = function(mutator_) {
    return this;
  };
  CatInterface_SetName_ResponseParams.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  CatInterface_SetName_ResponseParams.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  CatInterface_SetName_ResponseParams.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  CatInterface_SetName_ResponseParams.validate = function(messageValidator, offset) {
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

  CatInterface_SetName_ResponseParams.encodedSize = codec.kStructHeaderSize + 0;

  CatInterface_SetName_ResponseParams.decode = function(decoder) {
    var packed;
    var val = new CatInterface_SetName_ResponseParams();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    return val;
  };

  CatInterface_SetName_ResponseParams.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(CatInterface_SetName_ResponseParams.encodedSize);
    encoder.writeUint32(0);
  };
  function CatInterface_GetAge_Params(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  CatInterface_GetAge_Params.prototype.initDefaults_ = function() {
  };
  CatInterface_GetAge_Params.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  CatInterface_GetAge_Params.generate = function(generator_) {
    var generated = new CatInterface_GetAge_Params;
    return generated;
  };

  CatInterface_GetAge_Params.prototype.mutate = function(mutator_) {
    return this;
  };
  CatInterface_GetAge_Params.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  CatInterface_GetAge_Params.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  CatInterface_GetAge_Params.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  CatInterface_GetAge_Params.validate = function(messageValidator, offset) {
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

  CatInterface_GetAge_Params.encodedSize = codec.kStructHeaderSize + 0;

  CatInterface_GetAge_Params.decode = function(decoder) {
    var packed;
    var val = new CatInterface_GetAge_Params();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    return val;
  };

  CatInterface_GetAge_Params.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(CatInterface_GetAge_Params.encodedSize);
    encoder.writeUint32(0);
  };
  function CatInterface_GetAge_ResponseParams(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  CatInterface_GetAge_ResponseParams.prototype.initDefaults_ = function() {
    this.age = 0;
  };
  CatInterface_GetAge_ResponseParams.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  CatInterface_GetAge_ResponseParams.generate = function(generator_) {
    var generated = new CatInterface_GetAge_ResponseParams;
    generated.age = generator_.generateUint64();
    return generated;
  };

  CatInterface_GetAge_ResponseParams.prototype.mutate = function(mutator_) {
    if (mutator_.chooseMutateField()) {
      this.age = mutator_.mutateUint64(this.age);
    }
    return this;
  };
  CatInterface_GetAge_ResponseParams.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  CatInterface_GetAge_ResponseParams.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  CatInterface_GetAge_ResponseParams.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  CatInterface_GetAge_ResponseParams.validate = function(messageValidator, offset) {
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

  CatInterface_GetAge_ResponseParams.encodedSize = codec.kStructHeaderSize + 8;

  CatInterface_GetAge_ResponseParams.decode = function(decoder) {
    var packed;
    var val = new CatInterface_GetAge_ResponseParams();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    val.age = decoder.decodeStruct(codec.Uint64);
    return val;
  };

  CatInterface_GetAge_ResponseParams.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(CatInterface_GetAge_ResponseParams.encodedSize);
    encoder.writeUint32(0);
    encoder.encodeStruct(codec.Uint64, val.age);
  };
  function CatInterface_SetAge_Params(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  CatInterface_SetAge_Params.prototype.initDefaults_ = function() {
    this.newAge = 0;
  };
  CatInterface_SetAge_Params.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  CatInterface_SetAge_Params.generate = function(generator_) {
    var generated = new CatInterface_SetAge_Params;
    generated.newAge = generator_.generateUint64();
    return generated;
  };

  CatInterface_SetAge_Params.prototype.mutate = function(mutator_) {
    if (mutator_.chooseMutateField()) {
      this.newAge = mutator_.mutateUint64(this.newAge);
    }
    return this;
  };
  CatInterface_SetAge_Params.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  CatInterface_SetAge_Params.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  CatInterface_SetAge_Params.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  CatInterface_SetAge_Params.validate = function(messageValidator, offset) {
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

  CatInterface_SetAge_Params.encodedSize = codec.kStructHeaderSize + 8;

  CatInterface_SetAge_Params.decode = function(decoder) {
    var packed;
    var val = new CatInterface_SetAge_Params();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    val.newAge = decoder.decodeStruct(codec.Uint64);
    return val;
  };

  CatInterface_SetAge_Params.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(CatInterface_SetAge_Params.encodedSize);
    encoder.writeUint32(0);
    encoder.encodeStruct(codec.Uint64, val.newAge);
  };
  function CatInterface_SetAge_ResponseParams(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  CatInterface_SetAge_ResponseParams.prototype.initDefaults_ = function() {
  };
  CatInterface_SetAge_ResponseParams.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  CatInterface_SetAge_ResponseParams.generate = function(generator_) {
    var generated = new CatInterface_SetAge_ResponseParams;
    return generated;
  };

  CatInterface_SetAge_ResponseParams.prototype.mutate = function(mutator_) {
    return this;
  };
  CatInterface_SetAge_ResponseParams.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  CatInterface_SetAge_ResponseParams.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  CatInterface_SetAge_ResponseParams.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  CatInterface_SetAge_ResponseParams.validate = function(messageValidator, offset) {
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

  CatInterface_SetAge_ResponseParams.encodedSize = codec.kStructHeaderSize + 0;

  CatInterface_SetAge_ResponseParams.decode = function(decoder) {
    var packed;
    var val = new CatInterface_SetAge_ResponseParams();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    return val;
  };

  CatInterface_SetAge_ResponseParams.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(CatInterface_SetAge_ResponseParams.encodedSize);
    encoder.writeUint32(0);
  };
  function CatInterface_GetWeight_Params(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  CatInterface_GetWeight_Params.prototype.initDefaults_ = function() {
  };
  CatInterface_GetWeight_Params.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  CatInterface_GetWeight_Params.generate = function(generator_) {
    var generated = new CatInterface_GetWeight_Params;
    return generated;
  };

  CatInterface_GetWeight_Params.prototype.mutate = function(mutator_) {
    return this;
  };
  CatInterface_GetWeight_Params.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  CatInterface_GetWeight_Params.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  CatInterface_GetWeight_Params.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  CatInterface_GetWeight_Params.validate = function(messageValidator, offset) {
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

  CatInterface_GetWeight_Params.encodedSize = codec.kStructHeaderSize + 0;

  CatInterface_GetWeight_Params.decode = function(decoder) {
    var packed;
    var val = new CatInterface_GetWeight_Params();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    return val;
  };

  CatInterface_GetWeight_Params.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(CatInterface_GetWeight_Params.encodedSize);
    encoder.writeUint32(0);
  };
  function CatInterface_GetWeight_ResponseParams(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  CatInterface_GetWeight_ResponseParams.prototype.initDefaults_ = function() {
    this.weight = 0;
  };
  CatInterface_GetWeight_ResponseParams.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  CatInterface_GetWeight_ResponseParams.generate = function(generator_) {
    var generated = new CatInterface_GetWeight_ResponseParams;
    generated.weight = generator_.generateUint64();
    return generated;
  };

  CatInterface_GetWeight_ResponseParams.prototype.mutate = function(mutator_) {
    if (mutator_.chooseMutateField()) {
      this.weight = mutator_.mutateUint64(this.weight);
    }
    return this;
  };
  CatInterface_GetWeight_ResponseParams.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  CatInterface_GetWeight_ResponseParams.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  CatInterface_GetWeight_ResponseParams.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  CatInterface_GetWeight_ResponseParams.validate = function(messageValidator, offset) {
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

  CatInterface_GetWeight_ResponseParams.encodedSize = codec.kStructHeaderSize + 8;

  CatInterface_GetWeight_ResponseParams.decode = function(decoder) {
    var packed;
    var val = new CatInterface_GetWeight_ResponseParams();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    val.weight = decoder.decodeStruct(codec.Uint64);
    return val;
  };

  CatInterface_GetWeight_ResponseParams.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(CatInterface_GetWeight_ResponseParams.encodedSize);
    encoder.writeUint32(0);
    encoder.encodeStruct(codec.Uint64, val.weight);
  };
  function CatInterface_SetWeight_Params(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  CatInterface_SetWeight_Params.prototype.initDefaults_ = function() {
    this.newWeight = 0;
  };
  CatInterface_SetWeight_Params.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  CatInterface_SetWeight_Params.generate = function(generator_) {
    var generated = new CatInterface_SetWeight_Params;
    generated.newWeight = generator_.generateUint64();
    return generated;
  };

  CatInterface_SetWeight_Params.prototype.mutate = function(mutator_) {
    if (mutator_.chooseMutateField()) {
      this.newWeight = mutator_.mutateUint64(this.newWeight);
    }
    return this;
  };
  CatInterface_SetWeight_Params.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  CatInterface_SetWeight_Params.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  CatInterface_SetWeight_Params.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  CatInterface_SetWeight_Params.validate = function(messageValidator, offset) {
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

  CatInterface_SetWeight_Params.encodedSize = codec.kStructHeaderSize + 8;

  CatInterface_SetWeight_Params.decode = function(decoder) {
    var packed;
    var val = new CatInterface_SetWeight_Params();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    val.newWeight = decoder.decodeStruct(codec.Uint64);
    return val;
  };

  CatInterface_SetWeight_Params.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(CatInterface_SetWeight_Params.encodedSize);
    encoder.writeUint32(0);
    encoder.encodeStruct(codec.Uint64, val.newWeight);
  };
  function CatInterface_SetWeight_ResponseParams(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  CatInterface_SetWeight_ResponseParams.prototype.initDefaults_ = function() {
  };
  CatInterface_SetWeight_ResponseParams.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  CatInterface_SetWeight_ResponseParams.generate = function(generator_) {
    var generated = new CatInterface_SetWeight_ResponseParams;
    return generated;
  };

  CatInterface_SetWeight_ResponseParams.prototype.mutate = function(mutator_) {
    return this;
  };
  CatInterface_SetWeight_ResponseParams.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  CatInterface_SetWeight_ResponseParams.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  CatInterface_SetWeight_ResponseParams.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  CatInterface_SetWeight_ResponseParams.validate = function(messageValidator, offset) {
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

  CatInterface_SetWeight_ResponseParams.encodedSize = codec.kStructHeaderSize + 0;

  CatInterface_SetWeight_ResponseParams.decode = function(decoder) {
    var packed;
    var val = new CatInterface_SetWeight_ResponseParams();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    return val;
  };

  CatInterface_SetWeight_ResponseParams.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(CatInterface_SetWeight_ResponseParams.encodedSize);
    encoder.writeUint32(0);
  };
  function CatInterface_CookAndEat_Params(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  CatInterface_CookAndEat_Params.prototype.initDefaults_ = function() {
    this.food = new food_interface$.FoodInterfacePtr();
  };
  CatInterface_CookAndEat_Params.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  CatInterface_CookAndEat_Params.generate = function(generator_) {
    var generated = new CatInterface_CookAndEat_Params;
    generated.food = generator_.generateInterface("blink.mojom.FoodInterface", false);
    return generated;
  };

  CatInterface_CookAndEat_Params.prototype.mutate = function(mutator_) {
    if (mutator_.chooseMutateField()) {
      this.food = mutator_.mutateInterface(this.food, "blink.mojom.FoodInterface", false);
    }
    return this;
  };
  CatInterface_CookAndEat_Params.prototype.getHandleDeps = function() {
    var handles = [];
    if (this.food !== null) {
      Array.prototype.push.apply(handles, ["blink.mojom.FoodInterfacePtr"]);
    }
    return handles;
  };

  CatInterface_CookAndEat_Params.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  CatInterface_CookAndEat_Params.prototype.setHandlesInternal_ = function(handles, idx) {
    this.food = handles[idx++];;
    return idx;
  };

  CatInterface_CookAndEat_Params.validate = function(messageValidator, offset) {
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


    // validate CatInterface_CookAndEat_Params.food
    err = messageValidator.validateInterface(offset + codec.kStructHeaderSize + 0, false);
    if (err !== validator.validationError.NONE)
        return err;

    return validator.validationError.NONE;
  };

  CatInterface_CookAndEat_Params.encodedSize = codec.kStructHeaderSize + 8;

  CatInterface_CookAndEat_Params.decode = function(decoder) {
    var packed;
    var val = new CatInterface_CookAndEat_Params();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    val.food = decoder.decodeStruct(new codec.Interface(food_interface$.FoodInterfacePtr));
    return val;
  };

  CatInterface_CookAndEat_Params.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(CatInterface_CookAndEat_Params.encodedSize);
    encoder.writeUint32(0);
    encoder.encodeStruct(new codec.Interface(food_interface$.FoodInterfacePtr), val.food);
  };
  function CatInterface_CookAndEat_ResponseParams(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  CatInterface_CookAndEat_ResponseParams.prototype.initDefaults_ = function() {
  };
  CatInterface_CookAndEat_ResponseParams.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  CatInterface_CookAndEat_ResponseParams.generate = function(generator_) {
    var generated = new CatInterface_CookAndEat_ResponseParams;
    return generated;
  };

  CatInterface_CookAndEat_ResponseParams.prototype.mutate = function(mutator_) {
    return this;
  };
  CatInterface_CookAndEat_ResponseParams.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  CatInterface_CookAndEat_ResponseParams.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  CatInterface_CookAndEat_ResponseParams.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  CatInterface_CookAndEat_ResponseParams.validate = function(messageValidator, offset) {
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

  CatInterface_CookAndEat_ResponseParams.encodedSize = codec.kStructHeaderSize + 0;

  CatInterface_CookAndEat_ResponseParams.decode = function(decoder) {
    var packed;
    var val = new CatInterface_CookAndEat_ResponseParams();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    return val;
  };

  CatInterface_CookAndEat_ResponseParams.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(CatInterface_CookAndEat_ResponseParams.encodedSize);
    encoder.writeUint32(0);
  };
  var kCatInterface_GetName_Name = 1805329425;
  var kCatInterface_SetName_Name = 43287249;
  var kCatInterface_GetAge_Name = 2023360394;
  var kCatInterface_SetAge_Name = 2042883021;
  var kCatInterface_GetWeight_Name = 1623508494;
  var kCatInterface_SetWeight_Name = 22366822;
  var kCatInterface_CookAndEat_Name = 1774375151;

  function CatInterfacePtr(handleOrPtrInfo) {
    this.ptr = new bindings.InterfacePtrController(CatInterface,
                                                   handleOrPtrInfo);
  }

  function CatInterfaceAssociatedPtr(associatedInterfacePtrInfo) {
    this.ptr = new associatedBindings.AssociatedInterfacePtrController(
        CatInterface, associatedInterfacePtrInfo);
  }

  CatInterfaceAssociatedPtr.prototype =
      Object.create(CatInterfacePtr.prototype);
  CatInterfaceAssociatedPtr.prototype.constructor =
      CatInterfaceAssociatedPtr;

  function CatInterfaceProxy(receiver) {
    this.receiver_ = receiver;
  }
  CatInterfacePtr.prototype.getName = function() {
    return CatInterfaceProxy.prototype.getName
        .apply(this.ptr.getProxy(), arguments);
  };

  CatInterfaceProxy.prototype.getName = function() {
    var params_ = new CatInterface_GetName_Params();
    return new Promise(function(resolve, reject) {
      var builder = new codec.MessageV1Builder(
          kCatInterface_GetName_Name,
          codec.align(CatInterface_GetName_Params.encodedSize),
          codec.kMessageExpectsResponse, 0);
      builder.encodeStruct(CatInterface_GetName_Params, params_);
      var message = builder.finish();
      this.receiver_.acceptAndExpectResponse(message).then(function(message) {
        var reader = new codec.MessageReader(message);
        var responseParams =
            reader.decodeStruct(CatInterface_GetName_ResponseParams);
        resolve(responseParams);
      }).catch(function(result) {
        reject(Error("Connection error: " + result));
      });
    }.bind(this));
  };
  CatInterfacePtr.prototype.setName = function() {
    return CatInterfaceProxy.prototype.setName
        .apply(this.ptr.getProxy(), arguments);
  };

  CatInterfaceProxy.prototype.setName = function(newName) {
    var params_ = new CatInterface_SetName_Params();
    params_.newName = newName;
    return new Promise(function(resolve, reject) {
      var builder = new codec.MessageV1Builder(
          kCatInterface_SetName_Name,
          codec.align(CatInterface_SetName_Params.encodedSize),
          codec.kMessageExpectsResponse, 0);
      builder.encodeStruct(CatInterface_SetName_Params, params_);
      var message = builder.finish();
      this.receiver_.acceptAndExpectResponse(message).then(function(message) {
        var reader = new codec.MessageReader(message);
        var responseParams =
            reader.decodeStruct(CatInterface_SetName_ResponseParams);
        resolve(responseParams);
      }).catch(function(result) {
        reject(Error("Connection error: " + result));
      });
    }.bind(this));
  };
  CatInterfacePtr.prototype.getAge = function() {
    return CatInterfaceProxy.prototype.getAge
        .apply(this.ptr.getProxy(), arguments);
  };

  CatInterfaceProxy.prototype.getAge = function() {
    var params_ = new CatInterface_GetAge_Params();
    return new Promise(function(resolve, reject) {
      var builder = new codec.MessageV1Builder(
          kCatInterface_GetAge_Name,
          codec.align(CatInterface_GetAge_Params.encodedSize),
          codec.kMessageExpectsResponse, 0);
      builder.encodeStruct(CatInterface_GetAge_Params, params_);
      var message = builder.finish();
      this.receiver_.acceptAndExpectResponse(message).then(function(message) {
        var reader = new codec.MessageReader(message);
        var responseParams =
            reader.decodeStruct(CatInterface_GetAge_ResponseParams);
        resolve(responseParams);
      }).catch(function(result) {
        reject(Error("Connection error: " + result));
      });
    }.bind(this));
  };
  CatInterfacePtr.prototype.setAge = function() {
    return CatInterfaceProxy.prototype.setAge
        .apply(this.ptr.getProxy(), arguments);
  };

  CatInterfaceProxy.prototype.setAge = function(newAge) {
    var params_ = new CatInterface_SetAge_Params();
    params_.newAge = newAge;
    return new Promise(function(resolve, reject) {
      var builder = new codec.MessageV1Builder(
          kCatInterface_SetAge_Name,
          codec.align(CatInterface_SetAge_Params.encodedSize),
          codec.kMessageExpectsResponse, 0);
      builder.encodeStruct(CatInterface_SetAge_Params, params_);
      var message = builder.finish();
      this.receiver_.acceptAndExpectResponse(message).then(function(message) {
        var reader = new codec.MessageReader(message);
        var responseParams =
            reader.decodeStruct(CatInterface_SetAge_ResponseParams);
        resolve(responseParams);
      }).catch(function(result) {
        reject(Error("Connection error: " + result));
      });
    }.bind(this));
  };
  CatInterfacePtr.prototype.getWeight = function() {
    return CatInterfaceProxy.prototype.getWeight
        .apply(this.ptr.getProxy(), arguments);
  };

  CatInterfaceProxy.prototype.getWeight = function() {
    var params_ = new CatInterface_GetWeight_Params();
    return new Promise(function(resolve, reject) {
      var builder = new codec.MessageV1Builder(
          kCatInterface_GetWeight_Name,
          codec.align(CatInterface_GetWeight_Params.encodedSize),
          codec.kMessageExpectsResponse, 0);
      builder.encodeStruct(CatInterface_GetWeight_Params, params_);
      var message = builder.finish();
      this.receiver_.acceptAndExpectResponse(message).then(function(message) {
        var reader = new codec.MessageReader(message);
        var responseParams =
            reader.decodeStruct(CatInterface_GetWeight_ResponseParams);
        resolve(responseParams);
      }).catch(function(result) {
        reject(Error("Connection error: " + result));
      });
    }.bind(this));
  };
  CatInterfacePtr.prototype.setWeight = function() {
    return CatInterfaceProxy.prototype.setWeight
        .apply(this.ptr.getProxy(), arguments);
  };

  CatInterfaceProxy.prototype.setWeight = function(newWeight) {
    var params_ = new CatInterface_SetWeight_Params();
    params_.newWeight = newWeight;
    return new Promise(function(resolve, reject) {
      var builder = new codec.MessageV1Builder(
          kCatInterface_SetWeight_Name,
          codec.align(CatInterface_SetWeight_Params.encodedSize),
          codec.kMessageExpectsResponse, 0);
      builder.encodeStruct(CatInterface_SetWeight_Params, params_);
      var message = builder.finish();
      this.receiver_.acceptAndExpectResponse(message).then(function(message) {
        var reader = new codec.MessageReader(message);
        var responseParams =
            reader.decodeStruct(CatInterface_SetWeight_ResponseParams);
        resolve(responseParams);
      }).catch(function(result) {
        reject(Error("Connection error: " + result));
      });
    }.bind(this));
  };
  CatInterfacePtr.prototype.cookAndEat = function() {
    return CatInterfaceProxy.prototype.cookAndEat
        .apply(this.ptr.getProxy(), arguments);
  };

  CatInterfaceProxy.prototype.cookAndEat = function(food) {
    var params_ = new CatInterface_CookAndEat_Params();
    params_.food = food;
    return new Promise(function(resolve, reject) {
      var builder = new codec.MessageV1Builder(
          kCatInterface_CookAndEat_Name,
          codec.align(CatInterface_CookAndEat_Params.encodedSize),
          codec.kMessageExpectsResponse, 0);
      builder.encodeStruct(CatInterface_CookAndEat_Params, params_);
      var message = builder.finish();
      this.receiver_.acceptAndExpectResponse(message).then(function(message) {
        var reader = new codec.MessageReader(message);
        var responseParams =
            reader.decodeStruct(CatInterface_CookAndEat_ResponseParams);
        resolve(responseParams);
      }).catch(function(result) {
        reject(Error("Connection error: " + result));
      });
    }.bind(this));
  };

  function CatInterfaceStub(delegate) {
    this.delegate_ = delegate;
  }
  CatInterfaceStub.prototype.getName = function() {
    return this.delegate_ && this.delegate_.getName && this.delegate_.getName();
  }
  CatInterfaceStub.prototype.setName = function(newName) {
    return this.delegate_ && this.delegate_.setName && this.delegate_.setName(newName);
  }
  CatInterfaceStub.prototype.getAge = function() {
    return this.delegate_ && this.delegate_.getAge && this.delegate_.getAge();
  }
  CatInterfaceStub.prototype.setAge = function(newAge) {
    return this.delegate_ && this.delegate_.setAge && this.delegate_.setAge(newAge);
  }
  CatInterfaceStub.prototype.getWeight = function() {
    return this.delegate_ && this.delegate_.getWeight && this.delegate_.getWeight();
  }
  CatInterfaceStub.prototype.setWeight = function(newWeight) {
    return this.delegate_ && this.delegate_.setWeight && this.delegate_.setWeight(newWeight);
  }
  CatInterfaceStub.prototype.cookAndEat = function(food) {
    return this.delegate_ && this.delegate_.cookAndEat && this.delegate_.cookAndEat(food);
  }

  CatInterfaceStub.prototype.accept = function(message) {
    var reader = new codec.MessageReader(message);
    switch (reader.messageName) {
    default:
      return false;
    }
  };

  CatInterfaceStub.prototype.acceptWithResponder =
      function(message, responder) {
    var reader = new codec.MessageReader(message);
    switch (reader.messageName) {
    case kCatInterface_GetName_Name:
      var params = reader.decodeStruct(CatInterface_GetName_Params);
      this.getName().then(function(response) {
        var responseParams =
            new CatInterface_GetName_ResponseParams();
        responseParams.name = response.name;
        var builder = new codec.MessageV1Builder(
            kCatInterface_GetName_Name,
            codec.align(CatInterface_GetName_ResponseParams.encodedSize),
            codec.kMessageIsResponse, reader.requestID);
        builder.encodeStruct(CatInterface_GetName_ResponseParams,
                             responseParams);
        var message = builder.finish();
        responder.accept(message);
      });
      return true;
    case kCatInterface_SetName_Name:
      var params = reader.decodeStruct(CatInterface_SetName_Params);
      this.setName(params.newName).then(function(response) {
        var responseParams =
            new CatInterface_SetName_ResponseParams();
        var builder = new codec.MessageV1Builder(
            kCatInterface_SetName_Name,
            codec.align(CatInterface_SetName_ResponseParams.encodedSize),
            codec.kMessageIsResponse, reader.requestID);
        builder.encodeStruct(CatInterface_SetName_ResponseParams,
                             responseParams);
        var message = builder.finish();
        responder.accept(message);
      });
      return true;
    case kCatInterface_GetAge_Name:
      var params = reader.decodeStruct(CatInterface_GetAge_Params);
      this.getAge().then(function(response) {
        var responseParams =
            new CatInterface_GetAge_ResponseParams();
        responseParams.age = response.age;
        var builder = new codec.MessageV1Builder(
            kCatInterface_GetAge_Name,
            codec.align(CatInterface_GetAge_ResponseParams.encodedSize),
            codec.kMessageIsResponse, reader.requestID);
        builder.encodeStruct(CatInterface_GetAge_ResponseParams,
                             responseParams);
        var message = builder.finish();
        responder.accept(message);
      });
      return true;
    case kCatInterface_SetAge_Name:
      var params = reader.decodeStruct(CatInterface_SetAge_Params);
      this.setAge(params.newAge).then(function(response) {
        var responseParams =
            new CatInterface_SetAge_ResponseParams();
        var builder = new codec.MessageV1Builder(
            kCatInterface_SetAge_Name,
            codec.align(CatInterface_SetAge_ResponseParams.encodedSize),
            codec.kMessageIsResponse, reader.requestID);
        builder.encodeStruct(CatInterface_SetAge_ResponseParams,
                             responseParams);
        var message = builder.finish();
        responder.accept(message);
      });
      return true;
    case kCatInterface_GetWeight_Name:
      var params = reader.decodeStruct(CatInterface_GetWeight_Params);
      this.getWeight().then(function(response) {
        var responseParams =
            new CatInterface_GetWeight_ResponseParams();
        responseParams.weight = response.weight;
        var builder = new codec.MessageV1Builder(
            kCatInterface_GetWeight_Name,
            codec.align(CatInterface_GetWeight_ResponseParams.encodedSize),
            codec.kMessageIsResponse, reader.requestID);
        builder.encodeStruct(CatInterface_GetWeight_ResponseParams,
                             responseParams);
        var message = builder.finish();
        responder.accept(message);
      });
      return true;
    case kCatInterface_SetWeight_Name:
      var params = reader.decodeStruct(CatInterface_SetWeight_Params);
      this.setWeight(params.newWeight).then(function(response) {
        var responseParams =
            new CatInterface_SetWeight_ResponseParams();
        var builder = new codec.MessageV1Builder(
            kCatInterface_SetWeight_Name,
            codec.align(CatInterface_SetWeight_ResponseParams.encodedSize),
            codec.kMessageIsResponse, reader.requestID);
        builder.encodeStruct(CatInterface_SetWeight_ResponseParams,
                             responseParams);
        var message = builder.finish();
        responder.accept(message);
      });
      return true;
    case kCatInterface_CookAndEat_Name:
      var params = reader.decodeStruct(CatInterface_CookAndEat_Params);
      this.cookAndEat(params.food).then(function(response) {
        var responseParams =
            new CatInterface_CookAndEat_ResponseParams();
        var builder = new codec.MessageV1Builder(
            kCatInterface_CookAndEat_Name,
            codec.align(CatInterface_CookAndEat_ResponseParams.encodedSize),
            codec.kMessageIsResponse, reader.requestID);
        builder.encodeStruct(CatInterface_CookAndEat_ResponseParams,
                             responseParams);
        var message = builder.finish();
        responder.accept(message);
      });
      return true;
    default:
      return false;
    }
  };

  function validateCatInterfaceRequest(messageValidator) {
    var message = messageValidator.message;
    var paramsClass = null;
    switch (message.getName()) {
      case kCatInterface_GetName_Name:
        if (message.expectsResponse())
          paramsClass = CatInterface_GetName_Params;
      break;
      case kCatInterface_SetName_Name:
        if (message.expectsResponse())
          paramsClass = CatInterface_SetName_Params;
      break;
      case kCatInterface_GetAge_Name:
        if (message.expectsResponse())
          paramsClass = CatInterface_GetAge_Params;
      break;
      case kCatInterface_SetAge_Name:
        if (message.expectsResponse())
          paramsClass = CatInterface_SetAge_Params;
      break;
      case kCatInterface_GetWeight_Name:
        if (message.expectsResponse())
          paramsClass = CatInterface_GetWeight_Params;
      break;
      case kCatInterface_SetWeight_Name:
        if (message.expectsResponse())
          paramsClass = CatInterface_SetWeight_Params;
      break;
      case kCatInterface_CookAndEat_Name:
        if (message.expectsResponse())
          paramsClass = CatInterface_CookAndEat_Params;
      break;
    }
    if (paramsClass === null)
      return validator.validationError.NONE;
    return paramsClass.validate(messageValidator, messageValidator.message.getHeaderNumBytes());
  }

  function validateCatInterfaceResponse(messageValidator) {
   var message = messageValidator.message;
   var paramsClass = null;
   switch (message.getName()) {
      case kCatInterface_GetName_Name:
        if (message.isResponse())
          paramsClass = CatInterface_GetName_ResponseParams;
        break;
      case kCatInterface_SetName_Name:
        if (message.isResponse())
          paramsClass = CatInterface_SetName_ResponseParams;
        break;
      case kCatInterface_GetAge_Name:
        if (message.isResponse())
          paramsClass = CatInterface_GetAge_ResponseParams;
        break;
      case kCatInterface_SetAge_Name:
        if (message.isResponse())
          paramsClass = CatInterface_SetAge_ResponseParams;
        break;
      case kCatInterface_GetWeight_Name:
        if (message.isResponse())
          paramsClass = CatInterface_GetWeight_ResponseParams;
        break;
      case kCatInterface_SetWeight_Name:
        if (message.isResponse())
          paramsClass = CatInterface_SetWeight_ResponseParams;
        break;
      case kCatInterface_CookAndEat_Name:
        if (message.isResponse())
          paramsClass = CatInterface_CookAndEat_ResponseParams;
        break;
    }
    if (paramsClass === null)
      return validator.validationError.NONE;
    return paramsClass.validate(messageValidator, messageValidator.message.getHeaderNumBytes());
  }

  var CatInterface = {
    name: 'blink.mojom.CatInterface',
    kVersion: 0,
    ptrClass: CatInterfacePtr,
    proxyClass: CatInterfaceProxy,
    stubClass: CatInterfaceStub,
    validateRequest: validateCatInterfaceRequest,
    validateResponse: validateCatInterfaceResponse,
    mojomId: 'third_party/blink/public/mojom/CTF/cat_interface.mojom',
    fuzzMethods: {
      getName: {
        params: CatInterface_GetName_Params,
      },
      setName: {
        params: CatInterface_SetName_Params,
      },
      getAge: {
        params: CatInterface_GetAge_Params,
      },
      setAge: {
        params: CatInterface_SetAge_Params,
      },
      getWeight: {
        params: CatInterface_GetWeight_Params,
      },
      setWeight: {
        params: CatInterface_SetWeight_Params,
      },
      cookAndEat: {
        params: CatInterface_CookAndEat_Params,
      },
    },
  };
  CatInterfaceStub.prototype.validator = validateCatInterfaceRequest;
  CatInterfaceProxy.prototype.validator = validateCatInterfaceResponse;
  exports.CatInterface = CatInterface;
  exports.CatInterfacePtr = CatInterfacePtr;
  exports.CatInterfaceAssociatedPtr = CatInterfaceAssociatedPtr;
})();