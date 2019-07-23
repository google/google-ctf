// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

'use strict';

(function() {
  var mojomId = 'third_party/blink/public/mojom/CTF/food_interface.mojom';
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



  function FoodInterface_GetDescription_Params(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  FoodInterface_GetDescription_Params.prototype.initDefaults_ = function() {
  };
  FoodInterface_GetDescription_Params.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  FoodInterface_GetDescription_Params.generate = function(generator_) {
    var generated = new FoodInterface_GetDescription_Params;
    return generated;
  };

  FoodInterface_GetDescription_Params.prototype.mutate = function(mutator_) {
    return this;
  };
  FoodInterface_GetDescription_Params.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  FoodInterface_GetDescription_Params.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  FoodInterface_GetDescription_Params.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  FoodInterface_GetDescription_Params.validate = function(messageValidator, offset) {
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

  FoodInterface_GetDescription_Params.encodedSize = codec.kStructHeaderSize + 0;

  FoodInterface_GetDescription_Params.decode = function(decoder) {
    var packed;
    var val = new FoodInterface_GetDescription_Params();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    return val;
  };

  FoodInterface_GetDescription_Params.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(FoodInterface_GetDescription_Params.encodedSize);
    encoder.writeUint32(0);
  };
  function FoodInterface_GetDescription_ResponseParams(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  FoodInterface_GetDescription_ResponseParams.prototype.initDefaults_ = function() {
    this.description = null;
  };
  FoodInterface_GetDescription_ResponseParams.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  FoodInterface_GetDescription_ResponseParams.generate = function(generator_) {
    var generated = new FoodInterface_GetDescription_ResponseParams;
    generated.description = generator_.generateString(false);
    return generated;
  };

  FoodInterface_GetDescription_ResponseParams.prototype.mutate = function(mutator_) {
    if (mutator_.chooseMutateField()) {
      this.description = mutator_.mutateString(this.description, false);
    }
    return this;
  };
  FoodInterface_GetDescription_ResponseParams.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  FoodInterface_GetDescription_ResponseParams.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  FoodInterface_GetDescription_ResponseParams.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  FoodInterface_GetDescription_ResponseParams.validate = function(messageValidator, offset) {
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


    // validate FoodInterface_GetDescription_ResponseParams.description
    err = messageValidator.validateStringPointer(offset + codec.kStructHeaderSize + 0, false)
    if (err !== validator.validationError.NONE)
        return err;

    return validator.validationError.NONE;
  };

  FoodInterface_GetDescription_ResponseParams.encodedSize = codec.kStructHeaderSize + 8;

  FoodInterface_GetDescription_ResponseParams.decode = function(decoder) {
    var packed;
    var val = new FoodInterface_GetDescription_ResponseParams();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    val.description = decoder.decodeStruct(codec.String);
    return val;
  };

  FoodInterface_GetDescription_ResponseParams.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(FoodInterface_GetDescription_ResponseParams.encodedSize);
    encoder.writeUint32(0);
    encoder.encodeStruct(codec.String, val.description);
  };
  function FoodInterface_SetDescription_Params(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  FoodInterface_SetDescription_Params.prototype.initDefaults_ = function() {
    this.newDescription = null;
  };
  FoodInterface_SetDescription_Params.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  FoodInterface_SetDescription_Params.generate = function(generator_) {
    var generated = new FoodInterface_SetDescription_Params;
    generated.newDescription = generator_.generateString(false);
    return generated;
  };

  FoodInterface_SetDescription_Params.prototype.mutate = function(mutator_) {
    if (mutator_.chooseMutateField()) {
      this.newDescription = mutator_.mutateString(this.newDescription, false);
    }
    return this;
  };
  FoodInterface_SetDescription_Params.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  FoodInterface_SetDescription_Params.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  FoodInterface_SetDescription_Params.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  FoodInterface_SetDescription_Params.validate = function(messageValidator, offset) {
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


    // validate FoodInterface_SetDescription_Params.newDescription
    err = messageValidator.validateStringPointer(offset + codec.kStructHeaderSize + 0, false)
    if (err !== validator.validationError.NONE)
        return err;

    return validator.validationError.NONE;
  };

  FoodInterface_SetDescription_Params.encodedSize = codec.kStructHeaderSize + 8;

  FoodInterface_SetDescription_Params.decode = function(decoder) {
    var packed;
    var val = new FoodInterface_SetDescription_Params();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    val.newDescription = decoder.decodeStruct(codec.String);
    return val;
  };

  FoodInterface_SetDescription_Params.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(FoodInterface_SetDescription_Params.encodedSize);
    encoder.writeUint32(0);
    encoder.encodeStruct(codec.String, val.newDescription);
  };
  function FoodInterface_SetDescription_ResponseParams(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  FoodInterface_SetDescription_ResponseParams.prototype.initDefaults_ = function() {
  };
  FoodInterface_SetDescription_ResponseParams.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  FoodInterface_SetDescription_ResponseParams.generate = function(generator_) {
    var generated = new FoodInterface_SetDescription_ResponseParams;
    return generated;
  };

  FoodInterface_SetDescription_ResponseParams.prototype.mutate = function(mutator_) {
    return this;
  };
  FoodInterface_SetDescription_ResponseParams.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  FoodInterface_SetDescription_ResponseParams.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  FoodInterface_SetDescription_ResponseParams.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  FoodInterface_SetDescription_ResponseParams.validate = function(messageValidator, offset) {
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

  FoodInterface_SetDescription_ResponseParams.encodedSize = codec.kStructHeaderSize + 0;

  FoodInterface_SetDescription_ResponseParams.decode = function(decoder) {
    var packed;
    var val = new FoodInterface_SetDescription_ResponseParams();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    return val;
  };

  FoodInterface_SetDescription_ResponseParams.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(FoodInterface_SetDescription_ResponseParams.encodedSize);
    encoder.writeUint32(0);
  };
  function FoodInterface_GetWeight_Params(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  FoodInterface_GetWeight_Params.prototype.initDefaults_ = function() {
  };
  FoodInterface_GetWeight_Params.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  FoodInterface_GetWeight_Params.generate = function(generator_) {
    var generated = new FoodInterface_GetWeight_Params;
    return generated;
  };

  FoodInterface_GetWeight_Params.prototype.mutate = function(mutator_) {
    return this;
  };
  FoodInterface_GetWeight_Params.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  FoodInterface_GetWeight_Params.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  FoodInterface_GetWeight_Params.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  FoodInterface_GetWeight_Params.validate = function(messageValidator, offset) {
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

  FoodInterface_GetWeight_Params.encodedSize = codec.kStructHeaderSize + 0;

  FoodInterface_GetWeight_Params.decode = function(decoder) {
    var packed;
    var val = new FoodInterface_GetWeight_Params();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    return val;
  };

  FoodInterface_GetWeight_Params.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(FoodInterface_GetWeight_Params.encodedSize);
    encoder.writeUint32(0);
  };
  function FoodInterface_GetWeight_ResponseParams(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  FoodInterface_GetWeight_ResponseParams.prototype.initDefaults_ = function() {
    this.weight = 0;
  };
  FoodInterface_GetWeight_ResponseParams.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  FoodInterface_GetWeight_ResponseParams.generate = function(generator_) {
    var generated = new FoodInterface_GetWeight_ResponseParams;
    generated.weight = generator_.generateUint64();
    return generated;
  };

  FoodInterface_GetWeight_ResponseParams.prototype.mutate = function(mutator_) {
    if (mutator_.chooseMutateField()) {
      this.weight = mutator_.mutateUint64(this.weight);
    }
    return this;
  };
  FoodInterface_GetWeight_ResponseParams.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  FoodInterface_GetWeight_ResponseParams.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  FoodInterface_GetWeight_ResponseParams.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  FoodInterface_GetWeight_ResponseParams.validate = function(messageValidator, offset) {
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

  FoodInterface_GetWeight_ResponseParams.encodedSize = codec.kStructHeaderSize + 8;

  FoodInterface_GetWeight_ResponseParams.decode = function(decoder) {
    var packed;
    var val = new FoodInterface_GetWeight_ResponseParams();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    val.weight = decoder.decodeStruct(codec.Uint64);
    return val;
  };

  FoodInterface_GetWeight_ResponseParams.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(FoodInterface_GetWeight_ResponseParams.encodedSize);
    encoder.writeUint32(0);
    encoder.encodeStruct(codec.Uint64, val.weight);
  };
  function FoodInterface_SetWeight_Params(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  FoodInterface_SetWeight_Params.prototype.initDefaults_ = function() {
    this.newWeight = 0;
  };
  FoodInterface_SetWeight_Params.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  FoodInterface_SetWeight_Params.generate = function(generator_) {
    var generated = new FoodInterface_SetWeight_Params;
    generated.newWeight = generator_.generateUint64();
    return generated;
  };

  FoodInterface_SetWeight_Params.prototype.mutate = function(mutator_) {
    if (mutator_.chooseMutateField()) {
      this.newWeight = mutator_.mutateUint64(this.newWeight);
    }
    return this;
  };
  FoodInterface_SetWeight_Params.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  FoodInterface_SetWeight_Params.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  FoodInterface_SetWeight_Params.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  FoodInterface_SetWeight_Params.validate = function(messageValidator, offset) {
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

  FoodInterface_SetWeight_Params.encodedSize = codec.kStructHeaderSize + 8;

  FoodInterface_SetWeight_Params.decode = function(decoder) {
    var packed;
    var val = new FoodInterface_SetWeight_Params();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    val.newWeight = decoder.decodeStruct(codec.Uint64);
    return val;
  };

  FoodInterface_SetWeight_Params.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(FoodInterface_SetWeight_Params.encodedSize);
    encoder.writeUint32(0);
    encoder.encodeStruct(codec.Uint64, val.newWeight);
  };
  function FoodInterface_SetWeight_ResponseParams(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  FoodInterface_SetWeight_ResponseParams.prototype.initDefaults_ = function() {
  };
  FoodInterface_SetWeight_ResponseParams.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  FoodInterface_SetWeight_ResponseParams.generate = function(generator_) {
    var generated = new FoodInterface_SetWeight_ResponseParams;
    return generated;
  };

  FoodInterface_SetWeight_ResponseParams.prototype.mutate = function(mutator_) {
    return this;
  };
  FoodInterface_SetWeight_ResponseParams.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  FoodInterface_SetWeight_ResponseParams.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  FoodInterface_SetWeight_ResponseParams.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  FoodInterface_SetWeight_ResponseParams.validate = function(messageValidator, offset) {
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

  FoodInterface_SetWeight_ResponseParams.encodedSize = codec.kStructHeaderSize + 0;

  FoodInterface_SetWeight_ResponseParams.decode = function(decoder) {
    var packed;
    var val = new FoodInterface_SetWeight_ResponseParams();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    return val;
  };

  FoodInterface_SetWeight_ResponseParams.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(FoodInterface_SetWeight_ResponseParams.encodedSize);
    encoder.writeUint32(0);
  };
  var kFoodInterface_GetDescription_Name = 544620401;
  var kFoodInterface_SetDescription_Name = 1123297008;
  var kFoodInterface_GetWeight_Name = 2127222309;
  var kFoodInterface_SetWeight_Name = 1406869972;

  function FoodInterfacePtr(handleOrPtrInfo) {
    this.ptr = new bindings.InterfacePtrController(FoodInterface,
                                                   handleOrPtrInfo);
  }

  function FoodInterfaceAssociatedPtr(associatedInterfacePtrInfo) {
    this.ptr = new associatedBindings.AssociatedInterfacePtrController(
        FoodInterface, associatedInterfacePtrInfo);
  }

  FoodInterfaceAssociatedPtr.prototype =
      Object.create(FoodInterfacePtr.prototype);
  FoodInterfaceAssociatedPtr.prototype.constructor =
      FoodInterfaceAssociatedPtr;

  function FoodInterfaceProxy(receiver) {
    this.receiver_ = receiver;
  }
  FoodInterfacePtr.prototype.getDescription = function() {
    return FoodInterfaceProxy.prototype.getDescription
        .apply(this.ptr.getProxy(), arguments);
  };

  FoodInterfaceProxy.prototype.getDescription = function() {
    var params_ = new FoodInterface_GetDescription_Params();
    return new Promise(function(resolve, reject) {
      var builder = new codec.MessageV1Builder(
          kFoodInterface_GetDescription_Name,
          codec.align(FoodInterface_GetDescription_Params.encodedSize),
          codec.kMessageExpectsResponse, 0);
      builder.encodeStruct(FoodInterface_GetDescription_Params, params_);
      var message = builder.finish();
      this.receiver_.acceptAndExpectResponse(message).then(function(message) {
        var reader = new codec.MessageReader(message);
        var responseParams =
            reader.decodeStruct(FoodInterface_GetDescription_ResponseParams);
        resolve(responseParams);
      }).catch(function(result) {
        reject(Error("Connection error: " + result));
      });
    }.bind(this));
  };
  FoodInterfacePtr.prototype.setDescription = function() {
    return FoodInterfaceProxy.prototype.setDescription
        .apply(this.ptr.getProxy(), arguments);
  };

  FoodInterfaceProxy.prototype.setDescription = function(newDescription) {
    var params_ = new FoodInterface_SetDescription_Params();
    params_.newDescription = newDescription;
    return new Promise(function(resolve, reject) {
      var builder = new codec.MessageV1Builder(
          kFoodInterface_SetDescription_Name,
          codec.align(FoodInterface_SetDescription_Params.encodedSize),
          codec.kMessageExpectsResponse, 0);
      builder.encodeStruct(FoodInterface_SetDescription_Params, params_);
      var message = builder.finish();
      this.receiver_.acceptAndExpectResponse(message).then(function(message) {
        var reader = new codec.MessageReader(message);
        var responseParams =
            reader.decodeStruct(FoodInterface_SetDescription_ResponseParams);
        resolve(responseParams);
      }).catch(function(result) {
        reject(Error("Connection error: " + result));
      });
    }.bind(this));
  };
  FoodInterfacePtr.prototype.getWeight = function() {
    return FoodInterfaceProxy.prototype.getWeight
        .apply(this.ptr.getProxy(), arguments);
  };

  FoodInterfaceProxy.prototype.getWeight = function() {
    var params_ = new FoodInterface_GetWeight_Params();
    return new Promise(function(resolve, reject) {
      var builder = new codec.MessageV1Builder(
          kFoodInterface_GetWeight_Name,
          codec.align(FoodInterface_GetWeight_Params.encodedSize),
          codec.kMessageExpectsResponse, 0);
      builder.encodeStruct(FoodInterface_GetWeight_Params, params_);
      var message = builder.finish();
      this.receiver_.acceptAndExpectResponse(message).then(function(message) {
        var reader = new codec.MessageReader(message);
        var responseParams =
            reader.decodeStruct(FoodInterface_GetWeight_ResponseParams);
        resolve(responseParams);
      }).catch(function(result) {
        reject(Error("Connection error: " + result));
      });
    }.bind(this));
  };
  FoodInterfacePtr.prototype.setWeight = function() {
    return FoodInterfaceProxy.prototype.setWeight
        .apply(this.ptr.getProxy(), arguments);
  };

  FoodInterfaceProxy.prototype.setWeight = function(newWeight) {
    var params_ = new FoodInterface_SetWeight_Params();
    params_.newWeight = newWeight;
    return new Promise(function(resolve, reject) {
      var builder = new codec.MessageV1Builder(
          kFoodInterface_SetWeight_Name,
          codec.align(FoodInterface_SetWeight_Params.encodedSize),
          codec.kMessageExpectsResponse, 0);
      builder.encodeStruct(FoodInterface_SetWeight_Params, params_);
      var message = builder.finish();
      this.receiver_.acceptAndExpectResponse(message).then(function(message) {
        var reader = new codec.MessageReader(message);
        var responseParams =
            reader.decodeStruct(FoodInterface_SetWeight_ResponseParams);
        resolve(responseParams);
      }).catch(function(result) {
        reject(Error("Connection error: " + result));
      });
    }.bind(this));
  };

  function FoodInterfaceStub(delegate) {
    this.delegate_ = delegate;
  }
  FoodInterfaceStub.prototype.getDescription = function() {
    return this.delegate_ && this.delegate_.getDescription && this.delegate_.getDescription();
  }
  FoodInterfaceStub.prototype.setDescription = function(newDescription) {
    return this.delegate_ && this.delegate_.setDescription && this.delegate_.setDescription(newDescription);
  }
  FoodInterfaceStub.prototype.getWeight = function() {
    return this.delegate_ && this.delegate_.getWeight && this.delegate_.getWeight();
  }
  FoodInterfaceStub.prototype.setWeight = function(newWeight) {
    return this.delegate_ && this.delegate_.setWeight && this.delegate_.setWeight(newWeight);
  }

  FoodInterfaceStub.prototype.accept = function(message) {
    var reader = new codec.MessageReader(message);
    switch (reader.messageName) {
    default:
      return false;
    }
  };

  FoodInterfaceStub.prototype.acceptWithResponder =
      function(message, responder) {
    var reader = new codec.MessageReader(message);
    switch (reader.messageName) {
    case kFoodInterface_GetDescription_Name:
      var params = reader.decodeStruct(FoodInterface_GetDescription_Params);
      this.getDescription().then(function(response) {
        var responseParams =
            new FoodInterface_GetDescription_ResponseParams();
        responseParams.description = response.description;
        var builder = new codec.MessageV1Builder(
            kFoodInterface_GetDescription_Name,
            codec.align(FoodInterface_GetDescription_ResponseParams.encodedSize),
            codec.kMessageIsResponse, reader.requestID);
        builder.encodeStruct(FoodInterface_GetDescription_ResponseParams,
                             responseParams);
        var message = builder.finish();
        responder.accept(message);
      });
      return true;
    case kFoodInterface_SetDescription_Name:
      var params = reader.decodeStruct(FoodInterface_SetDescription_Params);
      this.setDescription(params.newDescription).then(function(response) {
        var responseParams =
            new FoodInterface_SetDescription_ResponseParams();
        var builder = new codec.MessageV1Builder(
            kFoodInterface_SetDescription_Name,
            codec.align(FoodInterface_SetDescription_ResponseParams.encodedSize),
            codec.kMessageIsResponse, reader.requestID);
        builder.encodeStruct(FoodInterface_SetDescription_ResponseParams,
                             responseParams);
        var message = builder.finish();
        responder.accept(message);
      });
      return true;
    case kFoodInterface_GetWeight_Name:
      var params = reader.decodeStruct(FoodInterface_GetWeight_Params);
      this.getWeight().then(function(response) {
        var responseParams =
            new FoodInterface_GetWeight_ResponseParams();
        responseParams.weight = response.weight;
        var builder = new codec.MessageV1Builder(
            kFoodInterface_GetWeight_Name,
            codec.align(FoodInterface_GetWeight_ResponseParams.encodedSize),
            codec.kMessageIsResponse, reader.requestID);
        builder.encodeStruct(FoodInterface_GetWeight_ResponseParams,
                             responseParams);
        var message = builder.finish();
        responder.accept(message);
      });
      return true;
    case kFoodInterface_SetWeight_Name:
      var params = reader.decodeStruct(FoodInterface_SetWeight_Params);
      this.setWeight(params.newWeight).then(function(response) {
        var responseParams =
            new FoodInterface_SetWeight_ResponseParams();
        var builder = new codec.MessageV1Builder(
            kFoodInterface_SetWeight_Name,
            codec.align(FoodInterface_SetWeight_ResponseParams.encodedSize),
            codec.kMessageIsResponse, reader.requestID);
        builder.encodeStruct(FoodInterface_SetWeight_ResponseParams,
                             responseParams);
        var message = builder.finish();
        responder.accept(message);
      });
      return true;
    default:
      return false;
    }
  };

  function validateFoodInterfaceRequest(messageValidator) {
    var message = messageValidator.message;
    var paramsClass = null;
    switch (message.getName()) {
      case kFoodInterface_GetDescription_Name:
        if (message.expectsResponse())
          paramsClass = FoodInterface_GetDescription_Params;
      break;
      case kFoodInterface_SetDescription_Name:
        if (message.expectsResponse())
          paramsClass = FoodInterface_SetDescription_Params;
      break;
      case kFoodInterface_GetWeight_Name:
        if (message.expectsResponse())
          paramsClass = FoodInterface_GetWeight_Params;
      break;
      case kFoodInterface_SetWeight_Name:
        if (message.expectsResponse())
          paramsClass = FoodInterface_SetWeight_Params;
      break;
    }
    if (paramsClass === null)
      return validator.validationError.NONE;
    return paramsClass.validate(messageValidator, messageValidator.message.getHeaderNumBytes());
  }

  function validateFoodInterfaceResponse(messageValidator) {
   var message = messageValidator.message;
   var paramsClass = null;
   switch (message.getName()) {
      case kFoodInterface_GetDescription_Name:
        if (message.isResponse())
          paramsClass = FoodInterface_GetDescription_ResponseParams;
        break;
      case kFoodInterface_SetDescription_Name:
        if (message.isResponse())
          paramsClass = FoodInterface_SetDescription_ResponseParams;
        break;
      case kFoodInterface_GetWeight_Name:
        if (message.isResponse())
          paramsClass = FoodInterface_GetWeight_ResponseParams;
        break;
      case kFoodInterface_SetWeight_Name:
        if (message.isResponse())
          paramsClass = FoodInterface_SetWeight_ResponseParams;
        break;
    }
    if (paramsClass === null)
      return validator.validationError.NONE;
    return paramsClass.validate(messageValidator, messageValidator.message.getHeaderNumBytes());
  }

  var FoodInterface = {
    name: 'blink.mojom.FoodInterface',
    kVersion: 0,
    ptrClass: FoodInterfacePtr,
    proxyClass: FoodInterfaceProxy,
    stubClass: FoodInterfaceStub,
    validateRequest: validateFoodInterfaceRequest,
    validateResponse: validateFoodInterfaceResponse,
    mojomId: 'third_party/blink/public/mojom/CTF/food_interface.mojom',
    fuzzMethods: {
      getDescription: {
        params: FoodInterface_GetDescription_Params,
      },
      setDescription: {
        params: FoodInterface_SetDescription_Params,
      },
      getWeight: {
        params: FoodInterface_GetWeight_Params,
      },
      setWeight: {
        params: FoodInterface_SetWeight_Params,
      },
    },
  };
  FoodInterfaceStub.prototype.validator = validateFoodInterfaceRequest;
  FoodInterfaceProxy.prototype.validator = validateFoodInterfaceResponse;
  exports.FoodInterface = FoodInterface;
  exports.FoodInterfacePtr = FoodInterfacePtr;
  exports.FoodInterfaceAssociatedPtr = FoodInterfaceAssociatedPtr;
})();