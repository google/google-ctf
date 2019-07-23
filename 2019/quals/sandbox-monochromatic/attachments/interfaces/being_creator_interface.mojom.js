// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

'use strict';

(function() {
  var mojomId = 'third_party/blink/public/mojom/CTF/being_creator_interface.mojom';
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
  var person_interface$ =
      mojo.internal.exposeNamespace('blink.mojom');
  if (mojo.config.autoLoadMojomDeps) {
    mojo.internal.loadMojomIfNecessary(
        'third_party/blink/public/mojom/CTF/person_interface.mojom', 'person_interface.mojom.js');
  }
  var dog_interface$ =
      mojo.internal.exposeNamespace('blink.mojom');
  if (mojo.config.autoLoadMojomDeps) {
    mojo.internal.loadMojomIfNecessary(
        'third_party/blink/public/mojom/CTF/dog_interface.mojom', 'dog_interface.mojom.js');
  }
  var cat_interface$ =
      mojo.internal.exposeNamespace('blink.mojom');
  if (mojo.config.autoLoadMojomDeps) {
    mojo.internal.loadMojomIfNecessary(
        'third_party/blink/public/mojom/CTF/cat_interface.mojom', 'cat_interface.mojom.js');
  }



  function BeingCreatorInterface_CreatePerson_Params(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  BeingCreatorInterface_CreatePerson_Params.prototype.initDefaults_ = function() {
  };
  BeingCreatorInterface_CreatePerson_Params.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  BeingCreatorInterface_CreatePerson_Params.generate = function(generator_) {
    var generated = new BeingCreatorInterface_CreatePerson_Params;
    return generated;
  };

  BeingCreatorInterface_CreatePerson_Params.prototype.mutate = function(mutator_) {
    return this;
  };
  BeingCreatorInterface_CreatePerson_Params.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  BeingCreatorInterface_CreatePerson_Params.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  BeingCreatorInterface_CreatePerson_Params.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  BeingCreatorInterface_CreatePerson_Params.validate = function(messageValidator, offset) {
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

  BeingCreatorInterface_CreatePerson_Params.encodedSize = codec.kStructHeaderSize + 0;

  BeingCreatorInterface_CreatePerson_Params.decode = function(decoder) {
    var packed;
    var val = new BeingCreatorInterface_CreatePerson_Params();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    return val;
  };

  BeingCreatorInterface_CreatePerson_Params.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(BeingCreatorInterface_CreatePerson_Params.encodedSize);
    encoder.writeUint32(0);
  };
  function BeingCreatorInterface_CreatePerson_ResponseParams(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  BeingCreatorInterface_CreatePerson_ResponseParams.prototype.initDefaults_ = function() {
    this.person = new person_interface$.PersonInterfacePtr();
  };
  BeingCreatorInterface_CreatePerson_ResponseParams.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  BeingCreatorInterface_CreatePerson_ResponseParams.generate = function(generator_) {
    var generated = new BeingCreatorInterface_CreatePerson_ResponseParams;
    generated.person = generator_.generateInterface("blink.mojom.PersonInterface", true);
    return generated;
  };

  BeingCreatorInterface_CreatePerson_ResponseParams.prototype.mutate = function(mutator_) {
    if (mutator_.chooseMutateField()) {
      this.person = mutator_.mutateInterface(this.person, "blink.mojom.PersonInterface", true);
    }
    return this;
  };
  BeingCreatorInterface_CreatePerson_ResponseParams.prototype.getHandleDeps = function() {
    var handles = [];
    if (this.person !== null) {
      Array.prototype.push.apply(handles, ["blink.mojom.PersonInterfacePtr"]);
    }
    return handles;
  };

  BeingCreatorInterface_CreatePerson_ResponseParams.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  BeingCreatorInterface_CreatePerson_ResponseParams.prototype.setHandlesInternal_ = function(handles, idx) {
    this.person = handles[idx++];;
    return idx;
  };

  BeingCreatorInterface_CreatePerson_ResponseParams.validate = function(messageValidator, offset) {
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


    // validate BeingCreatorInterface_CreatePerson_ResponseParams.person
    err = messageValidator.validateInterface(offset + codec.kStructHeaderSize + 0, true);
    if (err !== validator.validationError.NONE)
        return err;

    return validator.validationError.NONE;
  };

  BeingCreatorInterface_CreatePerson_ResponseParams.encodedSize = codec.kStructHeaderSize + 8;

  BeingCreatorInterface_CreatePerson_ResponseParams.decode = function(decoder) {
    var packed;
    var val = new BeingCreatorInterface_CreatePerson_ResponseParams();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    val.person = decoder.decodeStruct(new codec.NullableInterface(person_interface$.PersonInterfacePtr));
    return val;
  };

  BeingCreatorInterface_CreatePerson_ResponseParams.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(BeingCreatorInterface_CreatePerson_ResponseParams.encodedSize);
    encoder.writeUint32(0);
    encoder.encodeStruct(new codec.NullableInterface(person_interface$.PersonInterfacePtr), val.person);
  };
  function BeingCreatorInterface_CreateDog_Params(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  BeingCreatorInterface_CreateDog_Params.prototype.initDefaults_ = function() {
  };
  BeingCreatorInterface_CreateDog_Params.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  BeingCreatorInterface_CreateDog_Params.generate = function(generator_) {
    var generated = new BeingCreatorInterface_CreateDog_Params;
    return generated;
  };

  BeingCreatorInterface_CreateDog_Params.prototype.mutate = function(mutator_) {
    return this;
  };
  BeingCreatorInterface_CreateDog_Params.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  BeingCreatorInterface_CreateDog_Params.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  BeingCreatorInterface_CreateDog_Params.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  BeingCreatorInterface_CreateDog_Params.validate = function(messageValidator, offset) {
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

  BeingCreatorInterface_CreateDog_Params.encodedSize = codec.kStructHeaderSize + 0;

  BeingCreatorInterface_CreateDog_Params.decode = function(decoder) {
    var packed;
    var val = new BeingCreatorInterface_CreateDog_Params();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    return val;
  };

  BeingCreatorInterface_CreateDog_Params.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(BeingCreatorInterface_CreateDog_Params.encodedSize);
    encoder.writeUint32(0);
  };
  function BeingCreatorInterface_CreateDog_ResponseParams(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  BeingCreatorInterface_CreateDog_ResponseParams.prototype.initDefaults_ = function() {
    this.dog = new dog_interface$.DogInterfacePtr();
  };
  BeingCreatorInterface_CreateDog_ResponseParams.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  BeingCreatorInterface_CreateDog_ResponseParams.generate = function(generator_) {
    var generated = new BeingCreatorInterface_CreateDog_ResponseParams;
    generated.dog = generator_.generateInterface("blink.mojom.DogInterface", true);
    return generated;
  };

  BeingCreatorInterface_CreateDog_ResponseParams.prototype.mutate = function(mutator_) {
    if (mutator_.chooseMutateField()) {
      this.dog = mutator_.mutateInterface(this.dog, "blink.mojom.DogInterface", true);
    }
    return this;
  };
  BeingCreatorInterface_CreateDog_ResponseParams.prototype.getHandleDeps = function() {
    var handles = [];
    if (this.dog !== null) {
      Array.prototype.push.apply(handles, ["blink.mojom.DogInterfacePtr"]);
    }
    return handles;
  };

  BeingCreatorInterface_CreateDog_ResponseParams.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  BeingCreatorInterface_CreateDog_ResponseParams.prototype.setHandlesInternal_ = function(handles, idx) {
    this.dog = handles[idx++];;
    return idx;
  };

  BeingCreatorInterface_CreateDog_ResponseParams.validate = function(messageValidator, offset) {
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


    // validate BeingCreatorInterface_CreateDog_ResponseParams.dog
    err = messageValidator.validateInterface(offset + codec.kStructHeaderSize + 0, true);
    if (err !== validator.validationError.NONE)
        return err;

    return validator.validationError.NONE;
  };

  BeingCreatorInterface_CreateDog_ResponseParams.encodedSize = codec.kStructHeaderSize + 8;

  BeingCreatorInterface_CreateDog_ResponseParams.decode = function(decoder) {
    var packed;
    var val = new BeingCreatorInterface_CreateDog_ResponseParams();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    val.dog = decoder.decodeStruct(new codec.NullableInterface(dog_interface$.DogInterfacePtr));
    return val;
  };

  BeingCreatorInterface_CreateDog_ResponseParams.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(BeingCreatorInterface_CreateDog_ResponseParams.encodedSize);
    encoder.writeUint32(0);
    encoder.encodeStruct(new codec.NullableInterface(dog_interface$.DogInterfacePtr), val.dog);
  };
  function BeingCreatorInterface_CreateCat_Params(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  BeingCreatorInterface_CreateCat_Params.prototype.initDefaults_ = function() {
  };
  BeingCreatorInterface_CreateCat_Params.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  BeingCreatorInterface_CreateCat_Params.generate = function(generator_) {
    var generated = new BeingCreatorInterface_CreateCat_Params;
    return generated;
  };

  BeingCreatorInterface_CreateCat_Params.prototype.mutate = function(mutator_) {
    return this;
  };
  BeingCreatorInterface_CreateCat_Params.prototype.getHandleDeps = function() {
    var handles = [];
    return handles;
  };

  BeingCreatorInterface_CreateCat_Params.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  BeingCreatorInterface_CreateCat_Params.prototype.setHandlesInternal_ = function(handles, idx) {
    return idx;
  };

  BeingCreatorInterface_CreateCat_Params.validate = function(messageValidator, offset) {
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

  BeingCreatorInterface_CreateCat_Params.encodedSize = codec.kStructHeaderSize + 0;

  BeingCreatorInterface_CreateCat_Params.decode = function(decoder) {
    var packed;
    var val = new BeingCreatorInterface_CreateCat_Params();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    return val;
  };

  BeingCreatorInterface_CreateCat_Params.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(BeingCreatorInterface_CreateCat_Params.encodedSize);
    encoder.writeUint32(0);
  };
  function BeingCreatorInterface_CreateCat_ResponseParams(values) {
    this.initDefaults_();
    this.initFields_(values);
  }


  BeingCreatorInterface_CreateCat_ResponseParams.prototype.initDefaults_ = function() {
    this.cat = new cat_interface$.CatInterfacePtr();
  };
  BeingCreatorInterface_CreateCat_ResponseParams.prototype.initFields_ = function(fields) {
    for(var field in fields) {
        if (this.hasOwnProperty(field))
          this[field] = fields[field];
    }
  };
  BeingCreatorInterface_CreateCat_ResponseParams.generate = function(generator_) {
    var generated = new BeingCreatorInterface_CreateCat_ResponseParams;
    generated.cat = generator_.generateInterface("blink.mojom.CatInterface", true);
    return generated;
  };

  BeingCreatorInterface_CreateCat_ResponseParams.prototype.mutate = function(mutator_) {
    if (mutator_.chooseMutateField()) {
      this.cat = mutator_.mutateInterface(this.cat, "blink.mojom.CatInterface", true);
    }
    return this;
  };
  BeingCreatorInterface_CreateCat_ResponseParams.prototype.getHandleDeps = function() {
    var handles = [];
    if (this.cat !== null) {
      Array.prototype.push.apply(handles, ["blink.mojom.CatInterfacePtr"]);
    }
    return handles;
  };

  BeingCreatorInterface_CreateCat_ResponseParams.prototype.setHandles = function() {
    this.setHandlesInternal_(arguments, 0);
  };
  BeingCreatorInterface_CreateCat_ResponseParams.prototype.setHandlesInternal_ = function(handles, idx) {
    this.cat = handles[idx++];;
    return idx;
  };

  BeingCreatorInterface_CreateCat_ResponseParams.validate = function(messageValidator, offset) {
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


    // validate BeingCreatorInterface_CreateCat_ResponseParams.cat
    err = messageValidator.validateInterface(offset + codec.kStructHeaderSize + 0, true);
    if (err !== validator.validationError.NONE)
        return err;

    return validator.validationError.NONE;
  };

  BeingCreatorInterface_CreateCat_ResponseParams.encodedSize = codec.kStructHeaderSize + 8;

  BeingCreatorInterface_CreateCat_ResponseParams.decode = function(decoder) {
    var packed;
    var val = new BeingCreatorInterface_CreateCat_ResponseParams();
    var numberOfBytes = decoder.readUint32();
    var version = decoder.readUint32();
    val.cat = decoder.decodeStruct(new codec.NullableInterface(cat_interface$.CatInterfacePtr));
    return val;
  };

  BeingCreatorInterface_CreateCat_ResponseParams.encode = function(encoder, val) {
    var packed;
    encoder.writeUint32(BeingCreatorInterface_CreateCat_ResponseParams.encodedSize);
    encoder.writeUint32(0);
    encoder.encodeStruct(new codec.NullableInterface(cat_interface$.CatInterfacePtr), val.cat);
  };
  var kBeingCreatorInterface_CreatePerson_Name = 1621418558;
  var kBeingCreatorInterface_CreateDog_Name = 353558342;
  var kBeingCreatorInterface_CreateCat_Name = 1392292154;

  function BeingCreatorInterfacePtr(handleOrPtrInfo) {
    this.ptr = new bindings.InterfacePtrController(BeingCreatorInterface,
                                                   handleOrPtrInfo);
  }

  function BeingCreatorInterfaceAssociatedPtr(associatedInterfacePtrInfo) {
    this.ptr = new associatedBindings.AssociatedInterfacePtrController(
        BeingCreatorInterface, associatedInterfacePtrInfo);
  }

  BeingCreatorInterfaceAssociatedPtr.prototype =
      Object.create(BeingCreatorInterfacePtr.prototype);
  BeingCreatorInterfaceAssociatedPtr.prototype.constructor =
      BeingCreatorInterfaceAssociatedPtr;

  function BeingCreatorInterfaceProxy(receiver) {
    this.receiver_ = receiver;
  }
  BeingCreatorInterfacePtr.prototype.createPerson = function() {
    return BeingCreatorInterfaceProxy.prototype.createPerson
        .apply(this.ptr.getProxy(), arguments);
  };

  BeingCreatorInterfaceProxy.prototype.createPerson = function() {
    var params_ = new BeingCreatorInterface_CreatePerson_Params();
    return new Promise(function(resolve, reject) {
      var builder = new codec.MessageV1Builder(
          kBeingCreatorInterface_CreatePerson_Name,
          codec.align(BeingCreatorInterface_CreatePerson_Params.encodedSize),
          codec.kMessageExpectsResponse, 0);
      builder.encodeStruct(BeingCreatorInterface_CreatePerson_Params, params_);
      var message = builder.finish();
      this.receiver_.acceptAndExpectResponse(message).then(function(message) {
        var reader = new codec.MessageReader(message);
        var responseParams =
            reader.decodeStruct(BeingCreatorInterface_CreatePerson_ResponseParams);
        resolve(responseParams);
      }).catch(function(result) {
        reject(Error("Connection error: " + result));
      });
    }.bind(this));
  };
  BeingCreatorInterfacePtr.prototype.createDog = function() {
    return BeingCreatorInterfaceProxy.prototype.createDog
        .apply(this.ptr.getProxy(), arguments);
  };

  BeingCreatorInterfaceProxy.prototype.createDog = function() {
    var params_ = new BeingCreatorInterface_CreateDog_Params();
    return new Promise(function(resolve, reject) {
      var builder = new codec.MessageV1Builder(
          kBeingCreatorInterface_CreateDog_Name,
          codec.align(BeingCreatorInterface_CreateDog_Params.encodedSize),
          codec.kMessageExpectsResponse, 0);
      builder.encodeStruct(BeingCreatorInterface_CreateDog_Params, params_);
      var message = builder.finish();
      this.receiver_.acceptAndExpectResponse(message).then(function(message) {
        var reader = new codec.MessageReader(message);
        var responseParams =
            reader.decodeStruct(BeingCreatorInterface_CreateDog_ResponseParams);
        resolve(responseParams);
      }).catch(function(result) {
        reject(Error("Connection error: " + result));
      });
    }.bind(this));
  };
  BeingCreatorInterfacePtr.prototype.createCat = function() {
    return BeingCreatorInterfaceProxy.prototype.createCat
        .apply(this.ptr.getProxy(), arguments);
  };

  BeingCreatorInterfaceProxy.prototype.createCat = function() {
    var params_ = new BeingCreatorInterface_CreateCat_Params();
    return new Promise(function(resolve, reject) {
      var builder = new codec.MessageV1Builder(
          kBeingCreatorInterface_CreateCat_Name,
          codec.align(BeingCreatorInterface_CreateCat_Params.encodedSize),
          codec.kMessageExpectsResponse, 0);
      builder.encodeStruct(BeingCreatorInterface_CreateCat_Params, params_);
      var message = builder.finish();
      this.receiver_.acceptAndExpectResponse(message).then(function(message) {
        var reader = new codec.MessageReader(message);
        var responseParams =
            reader.decodeStruct(BeingCreatorInterface_CreateCat_ResponseParams);
        resolve(responseParams);
      }).catch(function(result) {
        reject(Error("Connection error: " + result));
      });
    }.bind(this));
  };

  function BeingCreatorInterfaceStub(delegate) {
    this.delegate_ = delegate;
  }
  BeingCreatorInterfaceStub.prototype.createPerson = function() {
    return this.delegate_ && this.delegate_.createPerson && this.delegate_.createPerson();
  }
  BeingCreatorInterfaceStub.prototype.createDog = function() {
    return this.delegate_ && this.delegate_.createDog && this.delegate_.createDog();
  }
  BeingCreatorInterfaceStub.prototype.createCat = function() {
    return this.delegate_ && this.delegate_.createCat && this.delegate_.createCat();
  }

  BeingCreatorInterfaceStub.prototype.accept = function(message) {
    var reader = new codec.MessageReader(message);
    switch (reader.messageName) {
    default:
      return false;
    }
  };

  BeingCreatorInterfaceStub.prototype.acceptWithResponder =
      function(message, responder) {
    var reader = new codec.MessageReader(message);
    switch (reader.messageName) {
    case kBeingCreatorInterface_CreatePerson_Name:
      var params = reader.decodeStruct(BeingCreatorInterface_CreatePerson_Params);
      this.createPerson().then(function(response) {
        var responseParams =
            new BeingCreatorInterface_CreatePerson_ResponseParams();
        responseParams.person = response.person;
        var builder = new codec.MessageV1Builder(
            kBeingCreatorInterface_CreatePerson_Name,
            codec.align(BeingCreatorInterface_CreatePerson_ResponseParams.encodedSize),
            codec.kMessageIsResponse, reader.requestID);
        builder.encodeStruct(BeingCreatorInterface_CreatePerson_ResponseParams,
                             responseParams);
        var message = builder.finish();
        responder.accept(message);
      });
      return true;
    case kBeingCreatorInterface_CreateDog_Name:
      var params = reader.decodeStruct(BeingCreatorInterface_CreateDog_Params);
      this.createDog().then(function(response) {
        var responseParams =
            new BeingCreatorInterface_CreateDog_ResponseParams();
        responseParams.dog = response.dog;
        var builder = new codec.MessageV1Builder(
            kBeingCreatorInterface_CreateDog_Name,
            codec.align(BeingCreatorInterface_CreateDog_ResponseParams.encodedSize),
            codec.kMessageIsResponse, reader.requestID);
        builder.encodeStruct(BeingCreatorInterface_CreateDog_ResponseParams,
                             responseParams);
        var message = builder.finish();
        responder.accept(message);
      });
      return true;
    case kBeingCreatorInterface_CreateCat_Name:
      var params = reader.decodeStruct(BeingCreatorInterface_CreateCat_Params);
      this.createCat().then(function(response) {
        var responseParams =
            new BeingCreatorInterface_CreateCat_ResponseParams();
        responseParams.cat = response.cat;
        var builder = new codec.MessageV1Builder(
            kBeingCreatorInterface_CreateCat_Name,
            codec.align(BeingCreatorInterface_CreateCat_ResponseParams.encodedSize),
            codec.kMessageIsResponse, reader.requestID);
        builder.encodeStruct(BeingCreatorInterface_CreateCat_ResponseParams,
                             responseParams);
        var message = builder.finish();
        responder.accept(message);
      });
      return true;
    default:
      return false;
    }
  };

  function validateBeingCreatorInterfaceRequest(messageValidator) {
    var message = messageValidator.message;
    var paramsClass = null;
    switch (message.getName()) {
      case kBeingCreatorInterface_CreatePerson_Name:
        if (message.expectsResponse())
          paramsClass = BeingCreatorInterface_CreatePerson_Params;
      break;
      case kBeingCreatorInterface_CreateDog_Name:
        if (message.expectsResponse())
          paramsClass = BeingCreatorInterface_CreateDog_Params;
      break;
      case kBeingCreatorInterface_CreateCat_Name:
        if (message.expectsResponse())
          paramsClass = BeingCreatorInterface_CreateCat_Params;
      break;
    }
    if (paramsClass === null)
      return validator.validationError.NONE;
    return paramsClass.validate(messageValidator, messageValidator.message.getHeaderNumBytes());
  }

  function validateBeingCreatorInterfaceResponse(messageValidator) {
   var message = messageValidator.message;
   var paramsClass = null;
   switch (message.getName()) {
      case kBeingCreatorInterface_CreatePerson_Name:
        if (message.isResponse())
          paramsClass = BeingCreatorInterface_CreatePerson_ResponseParams;
        break;
      case kBeingCreatorInterface_CreateDog_Name:
        if (message.isResponse())
          paramsClass = BeingCreatorInterface_CreateDog_ResponseParams;
        break;
      case kBeingCreatorInterface_CreateCat_Name:
        if (message.isResponse())
          paramsClass = BeingCreatorInterface_CreateCat_ResponseParams;
        break;
    }
    if (paramsClass === null)
      return validator.validationError.NONE;
    return paramsClass.validate(messageValidator, messageValidator.message.getHeaderNumBytes());
  }

  var BeingCreatorInterface = {
    name: 'blink.mojom.BeingCreatorInterface',
    kVersion: 0,
    ptrClass: BeingCreatorInterfacePtr,
    proxyClass: BeingCreatorInterfaceProxy,
    stubClass: BeingCreatorInterfaceStub,
    validateRequest: validateBeingCreatorInterfaceRequest,
    validateResponse: validateBeingCreatorInterfaceResponse,
    mojomId: 'third_party/blink/public/mojom/CTF/being_creator_interface.mojom',
    fuzzMethods: {
      createPerson: {
        params: BeingCreatorInterface_CreatePerson_Params,
      },
      createDog: {
        params: BeingCreatorInterface_CreateDog_Params,
      },
      createCat: {
        params: BeingCreatorInterface_CreateCat_Params,
      },
    },
  };
  BeingCreatorInterfaceStub.prototype.validator = validateBeingCreatorInterfaceRequest;
  BeingCreatorInterfaceProxy.prototype.validator = validateBeingCreatorInterfaceResponse;
  exports.BeingCreatorInterface = BeingCreatorInterface;
  exports.BeingCreatorInterfacePtr = BeingCreatorInterfacePtr;
  exports.BeingCreatorInterfaceAssociatedPtr = BeingCreatorInterfaceAssociatedPtr;
})();