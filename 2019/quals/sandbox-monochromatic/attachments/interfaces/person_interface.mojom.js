// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

'use strict';

(function() {
  var mojomId = 'third_party/blink/public/mojom/CTF/person_interface.mojom';
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



  function PersonInterface_GetName_Params(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  PersonInterface_GetName_Params.prototype.initDefaults_ = function() {
  };
  PersonInterface_GetName_Params.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  PersonInterface_GetName_Params.generate = function(generator_) {
    var generated = new PersonInterface_GetName_Params;
    return generated;
  };

  PersonInterface_GetName_Params.prototype.mutate = function(mutator_) {
    return this;
  };
  PersonInterface_GetName_Params.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  PersonInterface_GetName_Params.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  PersonInterface_GetName_Params.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  PersonInterface_GetName_Params.validate = function(messageValidator, offset) {
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

  PersonInterface_GetName_Params.encodedSize = codec.kStructHeaderSize + 0;

  PersonInterface_GetName_Params.decode = function(decoder) {
    var packed;
    var val = new PersonInterface_GetName_Params();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    return val;
  };

  PersonInterface_GetName_Params.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(PersonInterface_GetName_Params.encodedSize);
    encoder.writeUint32(0);
  };
  function PersonInterface_GetName_ResponseParams(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  PersonInterface_GetName_ResponseParams.prototype.initDefaults_ = function() {
    this.name = null;
  };
  PersonInterface_GetName_ResponseParams.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  PersonInterface_GetName_ResponseParams.generate = function(generator_) {
    var generated = new PersonInterface_GetName_ResponseParams;
    generated.name = generator_.generateString(false);
    return generated;
  };

  PersonInterface_GetName_ResponseParams.prototype.mutate = function(mutator_) {
    if (mutator_.chooseMutateField()) {
      this.name = mutator_.mutateString(this.name, false);
    }
    return this;
  };
  PersonInterface_GetName_ResponseParams.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  PersonInterface_GetName_ResponseParams.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  PersonInterface_GetName_ResponseParams.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  PersonInterface_GetName_ResponseParams.validate = function(messageValidator, offset) {
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


    // validate PersonInterface_GetName_ResponseParams.name
    err = messageValidator.validateStringPointer(offset + codec.kStructHeaderSize + 0, false)
    if (err !== validator.validationError.NONE)
        return err;

    return validator.validationError.NONE;
  };

  PersonInterface_GetName_ResponseParams.encodedSize = codec.kStructHeaderSize + 8;

  PersonInterface_GetName_ResponseParams.decode = function(decoder) {
    var packed;
    var val = new PersonInterface_GetName_ResponseParams();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    val.name = decoder.decodeStruct(codec.String);
    return val;
  };

  PersonInterface_GetName_ResponseParams.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(PersonInterface_GetName_ResponseParams.encodedSize);
    encoder.writeUint32(0);
    encoder.encodeStruct(codec.String, val.name);
  };
  function PersonInterface_SetName_Params(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  PersonInterface_SetName_Params.prototype.initDefaults_ = function() {
    this.newName = null;
  };
  PersonInterface_SetName_Params.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  PersonInterface_SetName_Params.generate = function(generator_) {
    var generated = new PersonInterface_SetName_Params;
    generated.newName = generator_.generateString(false);
    return generated;
  };

  PersonInterface_SetName_Params.prototype.mutate = function(mutator_) {
    if (mutator_.chooseMutateField()) {
      this.newName = mutator_.mutateString(this.newName, false);
    }
    return this;
  };
  PersonInterface_SetName_Params.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  PersonInterface_SetName_Params.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  PersonInterface_SetName_Params.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  PersonInterface_SetName_Params.validate = function(messageValidator, offset) {
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


    // validate PersonInterface_SetName_Params.newName
    err = messageValidator.validateStringPointer(offset + codec.kStructHeaderSize + 0, false)
    if (err !== validator.validationError.NONE)
        return err;

    return validator.validationError.NONE;
  };

  PersonInterface_SetName_Params.encodedSize = codec.kStructHeaderSize + 8;

  PersonInterface_SetName_Params.decode = function(decoder) {
    var packed;
    var val = new PersonInterface_SetName_Params();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    val.newName = decoder.decodeStruct(codec.String);
    return val;
  };

  PersonInterface_SetName_Params.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(PersonInterface_SetName_Params.encodedSize);
    encoder.writeUint32(0);
    encoder.encodeStruct(codec.String, val.newName);
  };
  function PersonInterface_SetName_ResponseParams(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  PersonInterface_SetName_ResponseParams.prototype.initDefaults_ = function() {
  };
  PersonInterface_SetName_ResponseParams.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  PersonInterface_SetName_ResponseParams.generate = function(generator_) {
    var generated = new PersonInterface_SetName_ResponseParams;
    return generated;
  };

  PersonInterface_SetName_ResponseParams.prototype.mutate = function(mutator_) {
    return this;
  };
  PersonInterface_SetName_ResponseParams.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  PersonInterface_SetName_ResponseParams.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  PersonInterface_SetName_ResponseParams.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  PersonInterface_SetName_ResponseParams.validate = function(messageValidator, offset) {
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

  PersonInterface_SetName_ResponseParams.encodedSize = codec.kStructHeaderSize + 0;

  PersonInterface_SetName_ResponseParams.decode = function(decoder) {
    var packed;
    var val = new PersonInterface_SetName_ResponseParams();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    return val;
  };

  PersonInterface_SetName_ResponseParams.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(PersonInterface_SetName_ResponseParams.encodedSize);
    encoder.writeUint32(0);
  };
  function PersonInterface_GetAge_Params(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  PersonInterface_GetAge_Params.prototype.initDefaults_ = function() {
  };
  PersonInterface_GetAge_Params.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  PersonInterface_GetAge_Params.generate = function(generator_) {
    var generated = new PersonInterface_GetAge_Params;
    return generated;
  };

  PersonInterface_GetAge_Params.prototype.mutate = function(mutator_) {
    return this;
  };
  PersonInterface_GetAge_Params.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  PersonInterface_GetAge_Params.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  PersonInterface_GetAge_Params.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  PersonInterface_GetAge_Params.validate = function(messageValidator, offset) {
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

  PersonInterface_GetAge_Params.encodedSize = codec.kStructHeaderSize + 0;

  PersonInterface_GetAge_Params.decode = function(decoder) {
    var packed;
    var val = new PersonInterface_GetAge_Params();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    return val;
  };

  PersonInterface_GetAge_Params.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(PersonInterface_GetAge_Params.encodedSize);
    encoder.writeUint32(0);
  };
  function PersonInterface_GetAge_ResponseParams(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  PersonInterface_GetAge_ResponseParams.prototype.initDefaults_ = function() {
    this.age = 0;
  };
  PersonInterface_GetAge_ResponseParams.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  PersonInterface_GetAge_ResponseParams.generate = function(generator_) {
    var generated = new PersonInterface_GetAge_ResponseParams;
    generated.age = generator_.generateUint64();
    return generated;
  };

  PersonInterface_GetAge_ResponseParams.prototype.mutate = function(mutator_) {
    if (mutator_.chooseMutateField()) {
      this.age = mutator_.mutateUint64(this.age);
    }
    return this;
  };
  PersonInterface_GetAge_ResponseParams.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  PersonInterface_GetAge_ResponseParams.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  PersonInterface_GetAge_ResponseParams.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  PersonInterface_GetAge_ResponseParams.validate = function(messageValidator, offset) {
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

  PersonInterface_GetAge_ResponseParams.encodedSize = codec.kStructHeaderSize + 8;

  PersonInterface_GetAge_ResponseParams.decode = function(decoder) {
    var packed;
    var val = new PersonInterface_GetAge_ResponseParams();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    val.age = decoder.decodeStruct(codec.Uint64);
    return val;
  };

  PersonInterface_GetAge_ResponseParams.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(PersonInterface_GetAge_ResponseParams.encodedSize);
    encoder.writeUint32(0);
    encoder.encodeStruct(codec.Uint64, val.age);
  };
  function PersonInterface_SetAge_Params(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  PersonInterface_SetAge_Params.prototype.initDefaults_ = function() {
    this.newAge = 0;
  };
  PersonInterface_SetAge_Params.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  PersonInterface_SetAge_Params.generate = function(generator_) {
    var generated = new PersonInterface_SetAge_Params;
    generated.newAge = generator_.generateUint64();
    return generated;
  };

  PersonInterface_SetAge_Params.prototype.mutate = function(mutator_) {
    if (mutator_.chooseMutateField()) {
      this.newAge = mutator_.mutateUint64(this.newAge);
    }
    return this;
  };
  PersonInterface_SetAge_Params.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  PersonInterface_SetAge_Params.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  PersonInterface_SetAge_Params.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  PersonInterface_SetAge_Params.validate = function(messageValidator, offset) {
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

  PersonInterface_SetAge_Params.encodedSize = codec.kStructHeaderSize + 8;

  PersonInterface_SetAge_Params.decode = function(decoder) {
    var packed;
    var val = new PersonInterface_SetAge_Params();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    val.newAge = decoder.decodeStruct(codec.Uint64);
    return val;
  };

  PersonInterface_SetAge_Params.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(PersonInterface_SetAge_Params.encodedSize);
    encoder.writeUint32(0);
    encoder.encodeStruct(codec.Uint64, val.newAge);
  };
  function PersonInterface_SetAge_ResponseParams(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  PersonInterface_SetAge_ResponseParams.prototype.initDefaults_ = function() {
  };
  PersonInterface_SetAge_ResponseParams.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  PersonInterface_SetAge_ResponseParams.generate = function(generator_) {
    var generated = new PersonInterface_SetAge_ResponseParams;
    return generated;
  };

  PersonInterface_SetAge_ResponseParams.prototype.mutate = function(mutator_) {
    return this;
  };
  PersonInterface_SetAge_ResponseParams.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  PersonInterface_SetAge_ResponseParams.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  PersonInterface_SetAge_ResponseParams.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  PersonInterface_SetAge_ResponseParams.validate = function(messageValidator, offset) {
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

  PersonInterface_SetAge_ResponseParams.encodedSize = codec.kStructHeaderSize + 0;

  PersonInterface_SetAge_ResponseParams.decode = function(decoder) {
    var packed;
    var val = new PersonInterface_SetAge_ResponseParams();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    return val;
  };

  PersonInterface_SetAge_ResponseParams.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(PersonInterface_SetAge_ResponseParams.encodedSize);
    encoder.writeUint32(0);
  };
  function PersonInterface_GetWeight_Params(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  PersonInterface_GetWeight_Params.prototype.initDefaults_ = function() {
  };
  PersonInterface_GetWeight_Params.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  PersonInterface_GetWeight_Params.generate = function(generator_) {
    var generated = new PersonInterface_GetWeight_Params;
    return generated;
  };

  PersonInterface_GetWeight_Params.prototype.mutate = function(mutator_) {
    return this;
  };
  PersonInterface_GetWeight_Params.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  PersonInterface_GetWeight_Params.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  PersonInterface_GetWeight_Params.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  PersonInterface_GetWeight_Params.validate = function(messageValidator, offset) {
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

  PersonInterface_GetWeight_Params.encodedSize = codec.kStructHeaderSize + 0;

  PersonInterface_GetWeight_Params.decode = function(decoder) {
    var packed;
    var val = new PersonInterface_GetWeight_Params();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    return val;
  };

  PersonInterface_GetWeight_Params.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(PersonInterface_GetWeight_Params.encodedSize);
    encoder.writeUint32(0);
  };
  function PersonInterface_GetWeight_ResponseParams(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  PersonInterface_GetWeight_ResponseParams.prototype.initDefaults_ = function() {
    this.weight = 0;
  };
  PersonInterface_GetWeight_ResponseParams.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  PersonInterface_GetWeight_ResponseParams.generate = function(generator_) {
    var generated = new PersonInterface_GetWeight_ResponseParams;
    generated.weight = generator_.generateUint64();
    return generated;
  };

  PersonInterface_GetWeight_ResponseParams.prototype.mutate = function(mutator_) {
    if (mutator_.chooseMutateField()) {
      this.weight = mutator_.mutateUint64(this.weight);
    }
    return this;
  };
  PersonInterface_GetWeight_ResponseParams.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  PersonInterface_GetWeight_ResponseParams.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  PersonInterface_GetWeight_ResponseParams.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  PersonInterface_GetWeight_ResponseParams.validate = function(messageValidator, offset) {
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

  PersonInterface_GetWeight_ResponseParams.encodedSize = codec.kStructHeaderSize + 8;

  PersonInterface_GetWeight_ResponseParams.decode = function(decoder) {
    var packed;
    var val = new PersonInterface_GetWeight_ResponseParams();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    val.weight = decoder.decodeStruct(codec.Uint64);
    return val;
  };

  PersonInterface_GetWeight_ResponseParams.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(PersonInterface_GetWeight_ResponseParams.encodedSize);
    encoder.writeUint32(0);
    encoder.encodeStruct(codec.Uint64, val.weight);
  };
  function PersonInterface_SetWeight_Params(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  PersonInterface_SetWeight_Params.prototype.initDefaults_ = function() {
    this.newWeight = 0;
  };
  PersonInterface_SetWeight_Params.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  PersonInterface_SetWeight_Params.generate = function(generator_) {
    var generated = new PersonInterface_SetWeight_Params;
    generated.newWeight = generator_.generateUint64();
    return generated;
  };

  PersonInterface_SetWeight_Params.prototype.mutate = function(mutator_) {
    if (mutator_.chooseMutateField()) {
      this.newWeight = mutator_.mutateUint64(this.newWeight);
    }
    return this;
  };
  PersonInterface_SetWeight_Params.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  PersonInterface_SetWeight_Params.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  PersonInterface_SetWeight_Params.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  PersonInterface_SetWeight_Params.validate = function(messageValidator, offset) {
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

  PersonInterface_SetWeight_Params.encodedSize = codec.kStructHeaderSize + 8;

  PersonInterface_SetWeight_Params.decode = function(decoder) {
    var packed;
    var val = new PersonInterface_SetWeight_Params();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    val.newWeight = decoder.decodeStruct(codec.Uint64);
    return val;
  };

  PersonInterface_SetWeight_Params.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(PersonInterface_SetWeight_Params.encodedSize);
    encoder.writeUint32(0);
    encoder.encodeStruct(codec.Uint64, val.newWeight);
  };
  function PersonInterface_SetWeight_ResponseParams(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  PersonInterface_SetWeight_ResponseParams.prototype.initDefaults_ = function() {
  };
  PersonInterface_SetWeight_ResponseParams.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  PersonInterface_SetWeight_ResponseParams.generate = function(generator_) {
    var generated = new PersonInterface_SetWeight_ResponseParams;
    return generated;
  };

  PersonInterface_SetWeight_ResponseParams.prototype.mutate = function(mutator_) {
    return this;
  };
  PersonInterface_SetWeight_ResponseParams.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  PersonInterface_SetWeight_ResponseParams.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  PersonInterface_SetWeight_ResponseParams.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  PersonInterface_SetWeight_ResponseParams.validate = function(messageValidator, offset) {
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

  PersonInterface_SetWeight_ResponseParams.encodedSize = codec.kStructHeaderSize + 0;

  PersonInterface_SetWeight_ResponseParams.decode = function(decoder) {
    var packed;
    var val = new PersonInterface_SetWeight_ResponseParams();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    return val;
  };

  PersonInterface_SetWeight_ResponseParams.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(PersonInterface_SetWeight_ResponseParams.encodedSize);
    encoder.writeUint32(0);
  };
  function PersonInterface_CookAndEat_Params(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  PersonInterface_CookAndEat_Params.prototype.initDefaults_ = function() {
    this.food = new food_interface$.FoodInterfacePtr();
  };
  PersonInterface_CookAndEat_Params.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  PersonInterface_CookAndEat_Params.generate = function(generator_) {
    var generated = new PersonInterface_CookAndEat_Params;
    generated.food = generator_.generateInterface("blink.mojom.FoodInterface", false);
    return generated;
  };

  PersonInterface_CookAndEat_Params.prototype.mutate = function(mutator_) {
    if (mutator_.chooseMutateField()) {
      this.food = mutator_.mutateInterface(this.food, "blink.mojom.FoodInterface", false);
    }
    return this;
  };
  PersonInterface_CookAndEat_Params.prototype.getHandleDeps = function() {
    var handles = [];
    if (this.food !== null) {
      Array.prototype.push.apply(handles, ["blink.mojom.FoodInterfacePtr"]);
    }
    return handles;
  };

  PersonInterface_CookAndEat_Params.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  PersonInterface_CookAndEat_Params.prototype.setHandlesInternal_ = function(handles, idx) {
    this.food = handles[idx++];;
    return idx;
  };

  PersonInterface_CookAndEat_Params.validate = function(messageValidator, offset) {
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


    // validate PersonInterface_CookAndEat_Params.food
    err = messageValidator.validateInterface(offset + codec.kStructHeaderSize + 0, false);
    if (err !== validator.validationError.NONE)
        return err;

    return validator.validationError.NONE;
  };

  PersonInterface_CookAndEat_Params.encodedSize = codec.kStructHeaderSize + 8;

  PersonInterface_CookAndEat_Params.decode = function(decoder) {
    var packed;
    var val = new PersonInterface_CookAndEat_Params();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    val.food = decoder.decodeStruct(new codec.Interface(food_interface$.FoodInterfacePtr));
    return val;
  };

  PersonInterface_CookAndEat_Params.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(PersonInterface_CookAndEat_Params.encodedSize);
    encoder.writeUint32(0);
    encoder.encodeStruct(new codec.Interface(food_interface$.FoodInterfacePtr), val.food);
  };
  function PersonInterface_CookAndEat_ResponseParams(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  PersonInterface_CookAndEat_ResponseParams.prototype.initDefaults_ = function() {
  };
  PersonInterface_CookAndEat_ResponseParams.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  PersonInterface_CookAndEat_ResponseParams.generate = function(generator_) {
    var generated = new PersonInterface_CookAndEat_ResponseParams;
    return generated;
  };

  PersonInterface_CookAndEat_ResponseParams.prototype.mutate = function(mutator_) {
    return this;
  };
  PersonInterface_CookAndEat_ResponseParams.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  PersonInterface_CookAndEat_ResponseParams.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  PersonInterface_CookAndEat_ResponseParams.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  PersonInterface_CookAndEat_ResponseParams.validate = function(messageValidator, offset) {
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

  PersonInterface_CookAndEat_ResponseParams.encodedSize = codec.kStructHeaderSize + 0;

  PersonInterface_CookAndEat_ResponseParams.decode = function(decoder) {
    var packed;
    var val = new PersonInterface_CookAndEat_ResponseParams();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    return val;
  };

  PersonInterface_CookAndEat_ResponseParams.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(PersonInterface_CookAndEat_ResponseParams.encodedSize);
    encoder.writeUint32(0);
  };
  var kPersonInterface_GetName_Name = 2031655346;
  var kPersonInterface_SetName_Name = 424119859;
  var kPersonInterface_GetAge_Name = 139256631;
  var kPersonInterface_SetAge_Name = 643719870;
  var kPersonInterface_GetWeight_Name = 1318402081;
  var kPersonInterface_SetWeight_Name = 726968327;
  var kPersonInterface_CookAndEat_Name = 83810605;

  function PersonInterfacePtr(handleOrPtrInfo) {
    this.ptr = new bindings.InterfacePtrController(PersonInterface,
                                                   handleOrPtrInfo);
  }

  function PersonInterfaceAssociatedPtr(associatedInterfacePtrInfo) {
    this.ptr = new associatedBindings.AssociatedInterfacePtrController(
        PersonInterface, associatedInterfacePtrInfo);
  }

  PersonInterfaceAssociatedPtr.prototype =
      Object.create(PersonInterfacePtr.prototype);
  PersonInterfaceAssociatedPtr.prototype.constructor =
      PersonInterfaceAssociatedPtr;

  function PersonInterfaceProxy(receiver) {
    this.receiver_ = receiver;
  }
  PersonInterfacePtr.prototype.getName = function() {
    return PersonInterfaceProxy.prototype.getName
        .apply(this.ptr.getProxy(), arguments);
  };

  PersonInterfaceProxy.prototype.getName = function() {
    var params_ = new PersonInterface_GetName_Params();
    return new Promise(function(resolve, reject) {
      var builder = new codec.MessageV1Builder(
          kPersonInterface_GetName_Name,
          codec.align(PersonInterface_GetName_Params.encodedSize),
          codec.kMessageExpectsResponse, 0);
      builder.encodeStruct(PersonInterface_GetName_Params, params_);
      var message = builder.finish();
      this.receiver_.acceptAndExpectResponse(message).then(function(message) {
        var reader = new codec.MessageReader(message);
        var responseParams =
            reader.decodeStruct(PersonInterface_GetName_ResponseParams);
        resolve(responseParams);
      }).catch(function(result) {
        reject(Error("Connection error: " + result));
      });
    }.bind(this));
  };
  PersonInterfacePtr.prototype.setName = function() {
    return PersonInterfaceProxy.prototype.setName
        .apply(this.ptr.getProxy(), arguments);
  };

  PersonInterfaceProxy.prototype.setName = function(newName) {
    var params_ = new PersonInterface_SetName_Params();
    params_.newName = newName;
    return new Promise(function(resolve, reject) {
      var builder = new codec.MessageV1Builder(
          kPersonInterface_SetName_Name,
          codec.align(PersonInterface_SetName_Params.encodedSize),
          codec.kMessageExpectsResponse, 0);
      builder.encodeStruct(PersonInterface_SetName_Params, params_);
      var message = builder.finish();
      this.receiver_.acceptAndExpectResponse(message).then(function(message) {
        var reader = new codec.MessageReader(message);
        var responseParams =
            reader.decodeStruct(PersonInterface_SetName_ResponseParams);
        resolve(responseParams);
      }).catch(function(result) {
        reject(Error("Connection error: " + result));
      });
    }.bind(this));
  };
  PersonInterfacePtr.prototype.getAge = function() {
    return PersonInterfaceProxy.prototype.getAge
        .apply(this.ptr.getProxy(), arguments);
  };

  PersonInterfaceProxy.prototype.getAge = function() {
    var params_ = new PersonInterface_GetAge_Params();
    return new Promise(function(resolve, reject) {
      var builder = new codec.MessageV1Builder(
          kPersonInterface_GetAge_Name,
          codec.align(PersonInterface_GetAge_Params.encodedSize),
          codec.kMessageExpectsResponse, 0);
      builder.encodeStruct(PersonInterface_GetAge_Params, params_);
      var message = builder.finish();
      this.receiver_.acceptAndExpectResponse(message).then(function(message) {
        var reader = new codec.MessageReader(message);
        var responseParams =
            reader.decodeStruct(PersonInterface_GetAge_ResponseParams);
        resolve(responseParams);
      }).catch(function(result) {
        reject(Error("Connection error: " + result));
      });
    }.bind(this));
  };
  PersonInterfacePtr.prototype.setAge = function() {
    return PersonInterfaceProxy.prototype.setAge
        .apply(this.ptr.getProxy(), arguments);
  };

  PersonInterfaceProxy.prototype.setAge = function(newAge) {
    var params_ = new PersonInterface_SetAge_Params();
    params_.newAge = newAge;
    return new Promise(function(resolve, reject) {
      var builder = new codec.MessageV1Builder(
          kPersonInterface_SetAge_Name,
          codec.align(PersonInterface_SetAge_Params.encodedSize),
          codec.kMessageExpectsResponse, 0);
      builder.encodeStruct(PersonInterface_SetAge_Params, params_);
      var message = builder.finish();
      this.receiver_.acceptAndExpectResponse(message).then(function(message) {
        var reader = new codec.MessageReader(message);
        var responseParams =
            reader.decodeStruct(PersonInterface_SetAge_ResponseParams);
        resolve(responseParams);
      }).catch(function(result) {
        reject(Error("Connection error: " + result));
      });
    }.bind(this));
  };
  PersonInterfacePtr.prototype.getWeight = function() {
    return PersonInterfaceProxy.prototype.getWeight
        .apply(this.ptr.getProxy(), arguments);
  };

  PersonInterfaceProxy.prototype.getWeight = function() {
    var params_ = new PersonInterface_GetWeight_Params();
    return new Promise(function(resolve, reject) {
      var builder = new codec.MessageV1Builder(
          kPersonInterface_GetWeight_Name,
          codec.align(PersonInterface_GetWeight_Params.encodedSize),
          codec.kMessageExpectsResponse, 0);
      builder.encodeStruct(PersonInterface_GetWeight_Params, params_);
      var message = builder.finish();
      this.receiver_.acceptAndExpectResponse(message).then(function(message) {
        var reader = new codec.MessageReader(message);
        var responseParams =
            reader.decodeStruct(PersonInterface_GetWeight_ResponseParams);
        resolve(responseParams);
      }).catch(function(result) {
        reject(Error("Connection error: " + result));
      });
    }.bind(this));
  };
  PersonInterfacePtr.prototype.setWeight = function() {
    return PersonInterfaceProxy.prototype.setWeight
        .apply(this.ptr.getProxy(), arguments);
  };

  PersonInterfaceProxy.prototype.setWeight = function(newWeight) {
    var params_ = new PersonInterface_SetWeight_Params();
    params_.newWeight = newWeight;
    return new Promise(function(resolve, reject) {
      var builder = new codec.MessageV1Builder(
          kPersonInterface_SetWeight_Name,
          codec.align(PersonInterface_SetWeight_Params.encodedSize),
          codec.kMessageExpectsResponse, 0);
      builder.encodeStruct(PersonInterface_SetWeight_Params, params_);
      var message = builder.finish();
      this.receiver_.acceptAndExpectResponse(message).then(function(message) {
        var reader = new codec.MessageReader(message);
        var responseParams =
            reader.decodeStruct(PersonInterface_SetWeight_ResponseParams);
        resolve(responseParams);
      }).catch(function(result) {
        reject(Error("Connection error: " + result));
      });
    }.bind(this));
  };
  PersonInterfacePtr.prototype.cookAndEat = function() {
    return PersonInterfaceProxy.prototype.cookAndEat
        .apply(this.ptr.getProxy(), arguments);
  };

  PersonInterfaceProxy.prototype.cookAndEat = function(food) {
    var params_ = new PersonInterface_CookAndEat_Params();
    params_.food = food;
    return new Promise(function(resolve, reject) {
      var builder = new codec.MessageV1Builder(
          kPersonInterface_CookAndEat_Name,
          codec.align(PersonInterface_CookAndEat_Params.encodedSize),
          codec.kMessageExpectsResponse, 0);
      builder.encodeStruct(PersonInterface_CookAndEat_Params, params_);
      var message = builder.finish();
      this.receiver_.acceptAndExpectResponse(message).then(function(message) {
        var reader = new codec.MessageReader(message);
        var responseParams =
            reader.decodeStruct(PersonInterface_CookAndEat_ResponseParams);
        resolve(responseParams);
      }).catch(function(result) {
        reject(Error("Connection error: " + result));
      });
    }.bind(this));
  };

  function PersonInterfaceStub(delegate) {
    this.delegate_ = delegate;
  }
  PersonInterfaceStub.prototype.getName = function() {
    return this.delegate_ && this.delegate_.getName && this.delegate_.getName();
  }
  PersonInterfaceStub.prototype.setName = function(newName) {
    return this.delegate_ && this.delegate_.setName && this.delegate_.setName(newName);
  }
  PersonInterfaceStub.prototype.getAge = function() {
    return this.delegate_ && this.delegate_.getAge && this.delegate_.getAge();
  }
  PersonInterfaceStub.prototype.setAge = function(newAge) {
    return this.delegate_ && this.delegate_.setAge && this.delegate_.setAge(newAge);
  }
  PersonInterfaceStub.prototype.getWeight = function() {
    return this.delegate_ && this.delegate_.getWeight && this.delegate_.getWeight();
  }
  PersonInterfaceStub.prototype.setWeight = function(newWeight) {
    return this.delegate_ && this.delegate_.setWeight && this.delegate_.setWeight(newWeight);
  }
  PersonInterfaceStub.prototype.cookAndEat = function(food) {
    return this.delegate_ && this.delegate_.cookAndEat && this.delegate_.cookAndEat(food);
  }

  PersonInterfaceStub.prototype.accept = function(message) {
    var reader = new codec.MessageReader(message);
    switch (reader.messageName) {
    default:
      return false;
    }
  };

  PersonInterfaceStub.prototype.acceptWithResponder =
      function(message, responder) {
    var reader = new codec.MessageReader(message);
    switch (reader.messageName) {
    case kPersonInterface_GetName_Name:
      var params = reader.decodeStruct(PersonInterface_GetName_Params);
      this.getName().then(function(response) {
        var responseParams =
            new PersonInterface_GetName_ResponseParams();
        responseParams.name = response.name;
        var builder = new codec.MessageV1Builder(
            kPersonInterface_GetName_Name,
            codec.align(PersonInterface_GetName_ResponseParams.encodedSize),
            codec.kMessageIsResponse, reader.requestID);
        builder.encodeStruct(PersonInterface_GetName_ResponseParams,
                             responseParams);
        var message = builder.finish();
        responder.accept(message);
      });
      return true;
    case kPersonInterface_SetName_Name:
      var params = reader.decodeStruct(PersonInterface_SetName_Params);
      this.setName(params.newName).then(function(response) {
        var responseParams =
            new PersonInterface_SetName_ResponseParams();
        var builder = new codec.MessageV1Builder(
            kPersonInterface_SetName_Name,
            codec.align(PersonInterface_SetName_ResponseParams.encodedSize),
            codec.kMessageIsResponse, reader.requestID);
        builder.encodeStruct(PersonInterface_SetName_ResponseParams,
                             responseParams);
        var message = builder.finish();
        responder.accept(message);
      });
      return true;
    case kPersonInterface_GetAge_Name:
      var params = reader.decodeStruct(PersonInterface_GetAge_Params);
      this.getAge().then(function(response) {
        var responseParams =
            new PersonInterface_GetAge_ResponseParams();
        responseParams.age = response.age;
        var builder = new codec.MessageV1Builder(
            kPersonInterface_GetAge_Name,
            codec.align(PersonInterface_GetAge_ResponseParams.encodedSize),
            codec.kMessageIsResponse, reader.requestID);
        builder.encodeStruct(PersonInterface_GetAge_ResponseParams,
                             responseParams);
        var message = builder.finish();
        responder.accept(message);
      });
      return true;
    case kPersonInterface_SetAge_Name:
      var params = reader.decodeStruct(PersonInterface_SetAge_Params);
      this.setAge(params.newAge).then(function(response) {
        var responseParams =
            new PersonInterface_SetAge_ResponseParams();
        var builder = new codec.MessageV1Builder(
            kPersonInterface_SetAge_Name,
            codec.align(PersonInterface_SetAge_ResponseParams.encodedSize),
            codec.kMessageIsResponse, reader.requestID);
        builder.encodeStruct(PersonInterface_SetAge_ResponseParams,
                             responseParams);
        var message = builder.finish();
        responder.accept(message);
      });
      return true;
    case kPersonInterface_GetWeight_Name:
      var params = reader.decodeStruct(PersonInterface_GetWeight_Params);
      this.getWeight().then(function(response) {
        var responseParams =
            new PersonInterface_GetWeight_ResponseParams();
        responseParams.weight = response.weight;
        var builder = new codec.MessageV1Builder(
            kPersonInterface_GetWeight_Name,
            codec.align(PersonInterface_GetWeight_ResponseParams.encodedSize),
            codec.kMessageIsResponse, reader.requestID);
        builder.encodeStruct(PersonInterface_GetWeight_ResponseParams,
                             responseParams);
        var message = builder.finish();
        responder.accept(message);
      });
      return true;
    case kPersonInterface_SetWeight_Name:
      var params = reader.decodeStruct(PersonInterface_SetWeight_Params);
      this.setWeight(params.newWeight).then(function(response) {
        var responseParams =
            new PersonInterface_SetWeight_ResponseParams();
        var builder = new codec.MessageV1Builder(
            kPersonInterface_SetWeight_Name,
            codec.align(PersonInterface_SetWeight_ResponseParams.encodedSize),
            codec.kMessageIsResponse, reader.requestID);
        builder.encodeStruct(PersonInterface_SetWeight_ResponseParams,
                             responseParams);
        var message = builder.finish();
        responder.accept(message);
      });
      return true;
    case kPersonInterface_CookAndEat_Name:
      var params = reader.decodeStruct(PersonInterface_CookAndEat_Params);
      this.cookAndEat(params.food).then(function(response) {
        var responseParams =
            new PersonInterface_CookAndEat_ResponseParams();
        var builder = new codec.MessageV1Builder(
            kPersonInterface_CookAndEat_Name,
            codec.align(PersonInterface_CookAndEat_ResponseParams.encodedSize),
            codec.kMessageIsResponse, reader.requestID);
        builder.encodeStruct(PersonInterface_CookAndEat_ResponseParams,
                             responseParams);
        var message = builder.finish();
        responder.accept(message);
      });
      return true;
    default:
      return false;
    }
  };

  function validatePersonInterfaceRequest(messageValidator) {
    var message = messageValidator.message;
    var paramsClass = null;
    switch (message.getName()) {
      case kPersonInterface_GetName_Name:
        if (message.expectsResponse())
          paramsClass = PersonInterface_GetName_Params;
      break;
      case kPersonInterface_SetName_Name:
        if (message.expectsResponse())
          paramsClass = PersonInterface_SetName_Params;
      break;
      case kPersonInterface_GetAge_Name:
        if (message.expectsResponse())
          paramsClass = PersonInterface_GetAge_Params;
      break;
      case kPersonInterface_SetAge_Name:
        if (message.expectsResponse())
          paramsClass = PersonInterface_SetAge_Params;
      break;
      case kPersonInterface_GetWeight_Name:
        if (message.expectsResponse())
          paramsClass = PersonInterface_GetWeight_Params;
      break;
      case kPersonInterface_SetWeight_Name:
        if (message.expectsResponse())
          paramsClass = PersonInterface_SetWeight_Params;
      break;
      case kPersonInterface_CookAndEat_Name:
        if (message.expectsResponse())
          paramsClass = PersonInterface_CookAndEat_Params;
      break;
    }
    if (paramsClass === null)
      return validator.validationError.NONE;
    return paramsClass.validate(messageValidator, messageValidator.message.getHeaderNumBytes());
  }

  function validatePersonInterfaceResponse(messageValidator) {
   var message = messageValidator.message;
   var paramsClass = null;
   switch (message.getName()) {
      case kPersonInterface_GetName_Name:
        if (message.isResponse())
          paramsClass = PersonInterface_GetName_ResponseParams;
        break;
      case kPersonInterface_SetName_Name:
        if (message.isResponse())
          paramsClass = PersonInterface_SetName_ResponseParams;
        break;
      case kPersonInterface_GetAge_Name:
        if (message.isResponse())
          paramsClass = PersonInterface_GetAge_ResponseParams;
        break;
      case kPersonInterface_SetAge_Name:
        if (message.isResponse())
          paramsClass = PersonInterface_SetAge_ResponseParams;
        break;
      case kPersonInterface_GetWeight_Name:
        if (message.isResponse())
          paramsClass = PersonInterface_GetWeight_ResponseParams;
        break;
      case kPersonInterface_SetWeight_Name:
        if (message.isResponse())
          paramsClass = PersonInterface_SetWeight_ResponseParams;
        break;
      case kPersonInterface_CookAndEat_Name:
        if (message.isResponse())
          paramsClass = PersonInterface_CookAndEat_ResponseParams;
        break;
    }
    if (paramsClass === null)
      return validator.validationError.NONE;
    return paramsClass.validate(messageValidator, messageValidator.message.getHeaderNumBytes());
  }

  var PersonInterface = {
    name: 'blink.mojom.PersonInterface',
    kVersion: 0,
    ptrClass: PersonInterfacePtr,
    proxyClass: PersonInterfaceProxy,
    stubClass: PersonInterfaceStub,
    validateRequest: validatePersonInterfaceRequest,
    validateResponse: validatePersonInterfaceResponse,
    mojomId: 'third_party/blink/public/mojom/CTF/person_interface.mojom',
    fuzzMethods: {
      getName: {
        params: PersonInterface_GetName_Params,
      },
      setName: {
        params: PersonInterface_SetName_Params,
      },
      getAge: {
        params: PersonInterface_GetAge_Params,
      },
      setAge: {
        params: PersonInterface_SetAge_Params,
      },
      getWeight: {
        params: PersonInterface_GetWeight_Params,
      },
      setWeight: {
        params: PersonInterface_SetWeight_Params,
      },
      cookAndEat: {
        params: PersonInterface_CookAndEat_Params,
      },
    },
  };
  PersonInterfaceStub.prototype.validator = validatePersonInterfaceRequest;
  PersonInterfaceProxy.prototype.validator = validatePersonInterfaceResponse;
  exports.PersonInterface = PersonInterface;
  exports.PersonInterfacePtr = PersonInterfacePtr;
  exports.PersonInterfaceAssociatedPtr = PersonInterfaceAssociatedPtr;
})();