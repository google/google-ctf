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



// ==ClosureCompiler==
// @compilation_level ADVANCED_OPTIMIZATIONS
// @output_file_name default.js
// ==/ClosureCompiler==



function uint8ArrayToBase64Url(uint8Array, start, end) {
  start = start || 0;
  end = end || uint8Array.byteLength;

  const base64 = window.btoa(
    String.fromCharCode.apply(null, uint8Array.subarray(start, end)));
  return base64
    .replace(/\=/g, '') // eslint-disable-line no-useless-escape
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

// Converts the URL-safe base64 encoded |base64UrlData| to an Uint8Array buffer.
function base64UrlToUint8Array(base64UrlData) {
  const padding = '='.repeat((4 - base64UrlData.length % 4) % 4);
  const base64 = (base64UrlData + padding)
    .replace(/\-/g, '+')
    .replace(/_/g, '/');

  const rawData = window.atob(base64);
  const buffer = new Uint8Array(rawData.length);

  for (let i = 0; i < rawData.length; ++i) {
    buffer[i] = rawData.charCodeAt(i);
  }
  return buffer;
}

// Super inefficient. But easier to follow than allocating the
// array with the correct size and position values in that array
// as required.
function joinUint8Arrays(allUint8Arrays) {
  return allUint8Arrays.reduce(function(cumulativeValue, nextValue) {
    if (!(nextValue instanceof Uint8Array)) {
      console.error('Received an non-Uint8Array value:', nextValue);
      throw new Error('Received an non-Uint8Array value.');
    }

    const joinedArray = new Uint8Array(
      cumulativeValue.byteLength + nextValue.byteLength
    );
    joinedArray.set(cumulativeValue, 0);
    joinedArray.set(nextValue, cumulativeValue.byteLength);
    return joinedArray;
  }, new Uint8Array());
}

function arrayBuffersToCryptoKeys(publicKey, privateKey) {
  // Length, in bytes, of a P-256 field element. Expected format of the private
  // key.
  const PRIVATE_KEY_BYTES = 32;

  // Length, in bytes, of a P-256 public key in uncompressed EC form per SEC
  // 2.3.3. This sequence must start with 0x04. Expected format of the
  // public key.
  const PUBLIC_KEY_BYTES = 65;

  if (publicKey.byteLength !== PUBLIC_KEY_BYTES) {
    throw new Error('The publicKey is expected to be ' +
      PUBLIC_KEY_BYTES + ' bytes.');
  }

  // Cast ArrayBuffer to Uint8Array
  const publicBuffer = new Uint8Array(publicKey);
  if (publicBuffer[0] !== 0x04) {
    throw new Error('The publicKey is expected to start with an ' +
      '0x04 byte.');
  }

  const jwk = {
    'kty': 'EC',
    'crv': 'P-256',
    'x': window.uint8ArrayToBase64Url(publicBuffer, 1, 33),
    'y': window.uint8ArrayToBase64Url(publicBuffer, 33, 65),
    'ext': true,
  };

  const keyPromises = [];
  keyPromises.push(crypto.subtle.importKey('jwk', jwk,
    {'name': 'ECDH', 'namedCurve': 'P-256'}, true, []));

  if (privateKey) {
    if (privateKey.byteLength !== PRIVATE_KEY_BYTES) {
      throw new Error('The privateKey is expected to be ' +
        PRIVATE_KEY_BYTES + ' bytes.');
    }

    // d must be defined after the importKey call for public
    jwk['d'] = window.uint8ArrayToBase64Url(privateKey);
    keyPromises.push(crypto.subtle.importKey('jwk', jwk,
      {'name': 'ECDH', 'namedCurve': 'P-256'}, true, ['deriveBits']));
  }

  return Promise.all(keyPromises)
  .then((keys) => {
    const keyPair = {
      publicKey: keys[0],
    };
    if (keys.length > 1) {
      keyPair.privateKey = keys[1];
    }
    return keyPair;
  });
}

function cryptoKeysToUint8Array(publicKey, privateKey) {
    return Promise.resolve()
    .then(() => {
      const promises = [];
      promises.push(
        crypto.subtle.exportKey('jwk', publicKey)
        .then((jwk) => {
          const x = window.base64UrlToUint8Array(jwk['x']);
          const y = window.base64UrlToUint8Array(jwk['y']);

          const publicKey = new Uint8Array(65);
          publicKey.set([0x04], 0);
          publicKey.set(x, 1);
          publicKey.set(y, 33);

          return publicKey;
        })
      );

      if (privateKey) {
        promises.push(
          crypto.subtle
            .exportKey('jwk', privateKey)
          .then((jwk) => {
            return window.base64UrlToUint8Array(jwk['d']);
          })
        );
      }

      return Promise.all(promises);
    })
    .then((exportedKeys) => {
      const result = {
        publicKey: exportedKeys[0],
      };

      if (exportedKeys.length > 1) {
        result.privateKey = exportedKeys[1];
      }

      return result;
    });
  }

  function generateSalt() {
    const SALT_BYTES = 16;
    return crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  }

if (window) {
  window.uint8ArrayToBase64Url = uint8ArrayToBase64Url;
  window.base64UrlToUint8Array = base64UrlToUint8Array;
  window.joinUint8Arrays = joinUint8Arrays;
  window.arrayBuffersToCryptoKeys = arrayBuffersToCryptoKeys;
  window.cryptoKeysToUint8Array = cryptoKeysToUint8Array;
  window.generateSalt = generateSalt;
} else if (module && module.exports) {
  module.exports = {
    uint8ArrayToBase64Url,
    base64UrlToUint8Array,
    joinUint8Arrays,
    arrayBuffersToCryptoKeys,
    cryptoKeysToUint8Array,
  };
}




class HMAC {
  constructor(ikm) {
    this._ikm = ikm;
  }

  sign(input) {
    return crypto.subtle.importKey('raw', this._ikm,
      {'name': 'HMAC', 'hash': 'SHA-256'}, false, ['sign'])
    .then((key) => {
      return crypto.subtle.sign('HMAC', key, input);
    });
  }
}

if (typeof window !== 'undefined') {
  window.gauntface = window.gauntface || {};
  window.gauntface.HMAC = HMAC;
} else if (module && module.exports) {
  module.exports = HMAC;
}
/* global HMAC */




class HKDF {
  constructor(ikm, salt) {
    this._ikm = ikm;
    this._salt = salt;

    this._hmac = new HMAC(salt);
  }

  generate(info, byteLength) {
    const fullInfoBuffer = new Uint8Array(info.byteLength + 1);
    fullInfoBuffer.set(info, 0);
    fullInfoBuffer.set(new Uint8Array(1).fill(1), info.byteLength);

    return this._hmac.sign(this._ikm)
    .then((prk) => {
      const nextHmac = new HMAC(prk);
      return nextHmac.sign(fullInfoBuffer);
    })
    .then((nextPrk) => {
      return nextPrk.slice(0, byteLength);
    });
  }
}

if (typeof window !== 'undefined') {
  window.gauntface = window.gauntface || {};
  window.gauntface.HKDF = HKDF;
} else if (module && module.exports) {
  module.exports = HKDF;
}
/**
 * PLEASE NOTE: This is in no way complete. This is just enabling
 * some testing in the browser / on github pages.
 *
 * Massive H/T to Peter Beverloo for this.
 */



class VapidHelper1 {
  static createVapidAuthHeader(vapidKeys, audience, subject, exp) {
    if (!audience) {
      return Promise.reject(new Error('Audience must be the origin of the ' +
        'server'));
    }

    if (!subject) {
      return Promise.reject(new Error('Subject must be either a mailto or ' +
        'http link'));
    }

    if (typeof exp !== 'number') {
      // The `exp` field will contain the current timestamp in UTC plus
      // twelve hours.
      exp = Math.floor((Date.now() / 1000) + 12 * 60 * 60);
    }

    const publicApplicationServerKey = window.base64UrlToUint8Array(
      vapidKeys.publicKey);
    const privateApplicationServerKey = window.base64UrlToUint8Array(
      vapidKeys.privateKey);

    // Ensure the audience is just the origin
    audience = new URL(audience).origin;

    const tokenHeader = {
      typ: 'JWT',
      alg: 'ES256',
    };

    const tokenBody = {
      aud: audience,
      exp: exp,
      sub: subject,
    };

    // Utility function for UTF-8 encoding a string to an ArrayBuffer.
    const utf8Encoder = new TextEncoder('utf-8');

    // The unsigned token is the concatenation of the URL-safe base64 encoded
    // header and body.
    const unsignedToken =
      window.uint8ArrayToBase64Url(
        utf8Encoder.encode(JSON.stringify(tokenHeader))
      ) + '.' + window.uint8ArrayToBase64Url(
        utf8Encoder.encode(JSON.stringify(tokenBody))
      );

    // Sign the |unsignedToken| using ES256 (SHA-256 over ECDSA).
    const key = {
      kty: 'EC',
      crv: 'P-256',
      x: window.uint8ArrayToBase64Url(
        publicApplicationServerKey.subarray(1, 33)),
      y: window.uint8ArrayToBase64Url(
        publicApplicationServerKey.subarray(33, 65)),
      d: window.uint8ArrayToBase64Url(privateApplicationServerKey),
    };

    // Sign the |unsignedToken| with the server's private key to generate
    // the signature.
    return crypto.subtle.importKey('jwk', key, {
      'name': 'ECDSA', 'namedCurve': 'P-256',
    }, true, ['sign'])
    .then((key) => {
      return crypto.subtle.sign({
        'name': 'ECDSA',
        'hash': {
          'name': 'SHA-256',
        },
      }, key, utf8Encoder.encode(unsignedToken));
    })
    .then((signature) => {
      const jsonWebToken = unsignedToken + '.' +
        window.uint8ArrayToBase64Url(new Uint8Array(signature));
      const p256ecdsa = window.uint8ArrayToBase64Url(
        publicApplicationServerKey);

      return {
        'Authorization': `WebPush ${jsonWebToken}`,
        'Crypto-Key': `p256ecdsa=${p256ecdsa}`,
      };
    });
  }
}

if (typeof window !== 'undefined') {
  window.gauntface = window.gauntface || {};
  window.gauntface.VapidHelper1 = VapidHelper1;
}
/**
 * PLEASE NOTE: This is in no way complete. This is just enabling
 * some testing in the browser / on github pages.
 *
 * Massive H/T to Peter Beverloo for this.
 */



class VapidHelper2 {
  static createVapidAuthHeader(vapidKeys, audience, subject, exp) {
    if (!audience) {
      return Promise.reject(new Error('Audience must be the origin of the ' +
        'server'));
    }

    if (!subject) {
      return Promise.reject(new Error('Subject must be either a mailto or ' +
        'http link'));
    }

    if (typeof exp !== 'number') {
      // The `exp` field will contain the current timestamp in UTC plus
      // twelve hours.
      exp = Math.floor((Date.now() / 1000) + 12 * 60 * 60);
    }

    const publicApplicationServerKey = window.base64UrlToUint8Array(
      vapidKeys.publicKey);
    const privateApplicationServerKey = window.base64UrlToUint8Array(
      vapidKeys.privateKey);

    // Ensure the audience is just the origin
    audience = new URL(audience).origin;

    const tokenHeader = {
      typ: 'JWT',
      alg: 'ES256',
    };

    const tokenBody = {
      aud: audience,
      exp: exp,
      sub: subject,
    };

    // Utility function for UTF-8 encoding a string to an ArrayBuffer.
    const utf8Encoder = new TextEncoder('utf-8');

    // The unsigned token is the concatenation of the URL-safe base64 encoded
    // header and body.
    const unsignedToken =
      window.uint8ArrayToBase64Url(
        utf8Encoder.encode(JSON.stringify(tokenHeader))
      ) + '.' + window.uint8ArrayToBase64Url(
        utf8Encoder.encode(JSON.stringify(tokenBody))
      );

    // Sign the |unsignedToken| using ES256 (SHA-256 over ECDSA).
    const key = {
      kty: 'EC',
      crv: 'P-256',
      x: window.uint8ArrayToBase64Url(
        publicApplicationServerKey.subarray(1, 33)),
      y: window.uint8ArrayToBase64Url(
        publicApplicationServerKey.subarray(33, 65)),
      d: window.uint8ArrayToBase64Url(privateApplicationServerKey),
    };

    // Sign the |unsignedToken| with the server's private key to generate
    // the signature.
    return crypto.subtle.importKey('jwk', key, {
      'name': 'ECDSA', 'namedCurve': 'P-256',
    }, true, ['sign'])
    .then((key) => {
      return crypto.subtle.sign({
        'name': 'ECDSA',
        'hash': {
          'name': 'SHA-256',
        },
      }, key, utf8Encoder.encode(unsignedToken));
    })
    .then((signature) => {
      const jsonWebToken = unsignedToken + '.' +
        window.uint8ArrayToBase64Url(new Uint8Array(signature));
      const p256ecdsa = window.uint8ArrayToBase64Url(
        publicApplicationServerKey);

      return {
        Authorization: `vapid t=${jsonWebToken}, k=${p256ecdsa}`,
      };
    });
  }
}

if (typeof window !== 'undefined') {
  window.gauntface = window.gauntface || {};
  window.gauntface.VapidHelper2 = VapidHelper2;
}

/* global HKDF */

class EncryptionHelperAES128GCM {
  constructor(options = {}) {
    this._b64ServerKeys = options.serverKeys;
    this._b64Salt = options.salt;
    this._b4VapidKeys = options.vapidKeys;
  }

  getServerKeys() {
    if (this._b64ServerKeys) {
      return window.arrayBuffersToCryptoKeys(
        window.base64UrlToUint8Array(this._b64ServerKeys.publicKey),
        window.base64UrlToUint8Array(this._b64ServerKeys.privateKey)
      );
    }

    return EncryptionHelperAES128GCM.generateServerKeys();
  }

  getSalt() {
    if (this._b64Salt) {
      return window.base64UrlToUint8Array(this._b64Salt);
    }

    return window.generateSalt();
  }

  getVapidKeys() {
    if (this._b4VapidKeys) {
      return this._b4VapidKeys;
    }

    return window.gauntface.CONSTANTS.APPLICATION_KEYS;
  }

  getRequestDetails(subscription, payloadText) {
    let vapidHelper = window.gauntface.VapidHelper1;

    let endpoint = subscription.endpoint;

    // Latest spec changes for VAPID is implemented on this custom FCM
    // endpoint. This is experimental and SHOULD NOT BE USED IN PRODUCTION
    // web apps.
    //
    // Need to get a proper feature detect in place for these vapid changes
    // https://github.com/mozilla-services/autopush/issues/879
    if (endpoint.indexOf('https://fcm.googleapis.com') === 0) {
      endpoint = endpoint.replace('fcm/send', 'wp');
      vapidHelper = window.gauntface.VapidHelper2;
    }

    return vapidHelper.createVapidAuthHeader(
      this.getVapidKeys(),
      subscription.endpoint,
      'mailto:simple-push-demo@gauntface.co.uk')
    .then((vapidHeaders) => {
      return this.encryptPayload(subscription, payloadText)
      .then((encryptedPayloadDetails) => {
        let body = null;
        const headers = {};
        headers.TTL = 60;

        if (encryptedPayloadDetails) {
          body = encryptedPayloadDetails.cipherText;
          headers['Content-Encoding'] = 'aes128gcm';
        } else {
          headers['Content-Length'] = 0;
        }

        if (vapidHeaders) {
          Object.keys(vapidHeaders).forEach((headerName) => {
            headers[headerName] = vapidHeaders[headerName];
          });
        }

        const response = {
          headers: headers,
          endpoint,
        };

        if (body) {
          response.body = body;
        }

        return Promise.resolve(response);
      });
    });
  }

  encryptPayload(subscription, payloadText) {
    if (!payloadText || payloadText.trim().length === 0) {
      return Promise.resolve(null);
    }

    const salt = this.getSalt();

    return this.getServerKeys()
    .then((serverKeys) => {
      return window.cryptoKeysToUint8Array(serverKeys.publicKey)
      .then((exportedServerKeys) => {
        return this._generateEncryptionKeys(subscription, salt, serverKeys)
        .then((encryptionKeys) => {
          return crypto.subtle.importKey('raw',
            encryptionKeys.contentEncryptionKey, 'AES-GCM', true,
            ['decrypt', 'encrypt'])
          .then((contentEncryptionCryptoKey) => {
            encryptionKeys.contentEncryptionCryptoKey =
              contentEncryptionCryptoKey;
            return encryptionKeys;
          });
        })
        .then((encryptionKeys) => {
          const utf8Encoder = new TextEncoder('utf-8');
          const payloadUint8Array = utf8Encoder.encode(payloadText);

          const paddingBytes = 0;
          const paddingUnit8Array = new Uint8Array(1 + paddingBytes);
          paddingUnit8Array.fill(0);
          paddingUnit8Array[0] = 0x02;

          const recordUint8Array = window.joinUint8Arrays([
            payloadUint8Array,
            paddingUnit8Array,
          ]);

          const algorithm = {
            'name': 'AES-GCM',
            'tagLength': 128,
            'iv': encryptionKeys.nonce,
          };

          return crypto.subtle.encrypt(
            algorithm, encryptionKeys.contentEncryptionCryptoKey,
            recordUint8Array
          );
        })
        .then((encryptedPayloadArrayBuffer) => {
          return this._addEncryptionContentCodingHeader(
            encryptedPayloadArrayBuffer,
            serverKeys,
            salt);
        })
        .then((encryptedPayloadArrayBuffer) => {
          return {
            cipherText: encryptedPayloadArrayBuffer,
            salt: window.uint8ArrayToBase64Url(salt),
            publicServerKey: window.uint8ArrayToBase64Url(
              exportedServerKeys.publicKey),
          };
        });
      });
    });
  }

  static generateServerKeys() {
    // 'true' is to make the keys extractable
    return crypto.subtle.generateKey({'name': 'ECDH', 'namedCurve': 'P-256'},
      true, ['deriveBits']);
  }

  _addEncryptionContentCodingHeader(
    encryptedPayloadArrayBuffer, serverKeys, salt) {
    return window.cryptoKeysToUint8Array(serverKeys.publicKey)
    .then((keys) => {
      // Maximum record size.
      const recordSizeUint8Array = new Uint8Array([0x00, 0x00, 0x10, 0x00]);

      const serverPublicKeyLengthBuffer = new Uint8Array(1);
      serverPublicKeyLengthBuffer[0] = keys.publicKey.byteLength;

      const uint8arrays = [
        salt,
        // Record Size
        recordSizeUint8Array,
        // Service Public Key Length
        serverPublicKeyLengthBuffer,
        // Server Public Key
        keys.publicKey,
        new Uint8Array(encryptedPayloadArrayBuffer),
      ];

      const joinedUint8Array = window.joinUint8Arrays(uint8arrays);
      return joinedUint8Array.buffer;
    });
  }

  _generateEncryptionKeys(subscription, salt, serverKeys) {
    return Promise.all([
      this._generatePRK(subscription, serverKeys),
      this._generateCEKInfo(subscription, serverKeys),
      this._generateNonceInfo(subscription, serverKeys),
    ])
    .then((results) => {
      const prk = results[0];j
      const cekInfo = results[1];
      const nonceInfo = results[2];

      const cekHKDF = new HKDF(prk, salt);
      const nonceHKDF = new HKDF(prk, salt);
      return Promise.all([
        cekHKDF.generate(cekInfo, 16),
        nonceHKDF.generate(nonceInfo, 12),
      ]);
    })
    .then((results) => {
      return {
        'contentEncryptionKey': results[0],
        'nonce': results[1],
      };
    });
  }

  _generateCEKInfo(subscription, serverKeys) {
    return Promise.resolve()
    .then(() => {
      const utf8Encoder = new TextEncoder('utf-8');
      const contentEncoding8Array = utf8Encoder
        .encode('Content-Encoding: aes128gcm');
      const paddingUnit8Array = new Uint8Array(1).fill(0);
      return window.joinUint8Arrays([
          contentEncoding8Array,
          paddingUnit8Array,
        ]);
    });
  }

  _generateNonceInfo(subscription, serverKeys) {
    return Promise.resolve()
    .then(() => {
      const utf8Encoder = new TextEncoder('utf-8');
      const contentEncoding8Array = utf8Encoder
        .encode('Content-Encoding: nonce');
      const paddingUnit8Array = new Uint8Array(1).fill(0);
      return window.joinUint8Arrays([
          contentEncoding8Array,
          paddingUnit8Array,
        ]);
    });
  }

  _generatePRK(subscription, serverKeys) {
    return this._getSharedSecret(subscription, serverKeys)
    .then((sharedSecret) => {
      return this._getKeyInfo(subscription, serverKeys)
      .then((keyInfoUint8Array) => {
        const hkdf = new HKDF(
        sharedSecret,
        subscription.getKey('auth'));
        return hkdf.generate(keyInfoUint8Array, 32);
      });
    });
  }

  _getSharedSecret(subscription, serverKeys) {
    return Promise.resolve()
    .then(() => {
      return window.arrayBuffersToCryptoKeys(subscription.getKey('p256dh'));
    })
    .then((keys) => {
      return keys.publicKey;
    })
    .then((publicKey) => {
      if (!(publicKey instanceof CryptoKey)) {
        throw new Error('The publicKey must be a CryptoKey.');
      }

      const algorithm = {
        name: 'ECDH',
        namedCurve: 'P-256',
        public: publicKey,
      };

      return crypto.subtle.deriveBits(
        algorithm, serverKeys.privateKey, 256);
    });
  }

  _getKeyInfo(subscription, serverKeys) {
    const utf8Encoder = new TextEncoder('utf-8');

    return window.cryptoKeysToUint8Array(serverKeys.publicKey)
    .then((serverKeys) => {
      return window.joinUint8Arrays([
        utf8Encoder.encode('WebPush: info'),
        new Uint8Array(1).fill(0),
        new Uint8Array(subscription.getKey('p256dh')),
        serverKeys.publicKey,
      ]);
    });
  }
}

if (typeof window !== 'undefined') {
  window.gauntface = window.gauntface || {};
  window.gauntface.EncryptionHelperAES128GCM = EncryptionHelperAES128GCM;
}

/* global HKDF */

class EncryptionHelperAESGCM {
  constructor(options = {}) {
    this._b64ServerKeys = options.serverKeys;
    this._b64Salt = options.salt;
    this._b4VapidKeys = options.vapidKeys;
  }

  getServerKeys() {
    if (this._b64ServerKeys) {
      return window.arrayBuffersToCryptoKeys(
        window.base64UrlToUint8Array(this._b64ServerKeys.publicKey),
        window.base64UrlToUint8Array(this._b64ServerKeys.privateKey)
      );
    }

    return EncryptionHelperAESGCM.generateServerKeys();
  }

  getSalt() {
    if (this._b64Salt) {
      return window.base64UrlToUint8Array(this._b64Salt);
    }

    return window.generateSalt();
  }

  getVapidKeys() {
    if (this._b4VapidKeys) {
      return this._b4VapidKeys;
    }

    return window.gauntface.CONSTANTS.APPLICATION_KEYS;
  }

  getRequestDetails(subscription, payloadText) {
    return VapidHelper1.createVapidAuthHeader(
      this.getVapidKeys(),
      subscription.endpoint,
      'mailto:simple-push-demo@gauntface.co.uk')
    .then((vapidHeaders) => {
      return this.encryptPayload(subscription, payloadText)
      .then((encryptedPayloadDetails) => {
        let body = null;
        const headers = {};
        headers.TTL = 60;

        if (encryptedPayloadDetails) {
          body = encryptedPayloadDetails.cipherText;

          headers.Encryption = `salt=${encryptedPayloadDetails.salt}`;
          headers['Crypto-Key'] =
            `dh=${encryptedPayloadDetails.publicServerKey}`;
          headers['Content-Encoding'] = 'aesgcm';
        } else {
          headers['Content-Length'] = 0;
        }

        if (vapidHeaders) {
          Object.keys(vapidHeaders).forEach((headerName) => {
            if (headers[headerName]) {
              headers[headerName] =
                `${headers[headerName]}; ${vapidHeaders[headerName]}`;
            } else {
              headers[headerName] = vapidHeaders[headerName];
            }
          });
        }

        const response = {
          headers: headers,
          endpoint: subscription.endpoint,
        };

        if (body) {
          response.body = body;
        }

        return Promise.resolve(response);
      });
    });
  }

  encryptPayload(subscription, payloadText) {
    if (!payloadText || payloadText.trim().length === 0) {
      return Promise.resolve(null);
    }

    const salt = this.getSalt();

    return this.getServerKeys()
    .then((serverKeys) => {
      return window.cryptoKeysToUint8Array(serverKeys.publicKey)
      .then((exportedServerKeys) => {
        return this._generateEncryptionKeys(subscription, salt, serverKeys)
        .then((encryptionKeys) => {
          return crypto.subtle.importKey('raw',
            encryptionKeys.contentEncryptionKey, 'AES-GCM', true,
            ['decrypt', 'encrypt'])
          .then((contentEncryptionCryptoKey) => {
            encryptionKeys.contentEncryptionCryptoKey =
              contentEncryptionCryptoKey;
            return encryptionKeys;
          });
        })
        .then((encryptionKeys) => {
          const paddingBytes = 0;
          const paddingUnit8Array = new Uint8Array(2 + paddingBytes);
          const utf8Encoder = new TextEncoder('utf-8');
          const payloadUint8Array = utf8Encoder.encode(payloadText);
          const recordUint8Array = new Uint8Array(
            paddingUnit8Array.byteLength + payloadUint8Array.byteLength);
          recordUint8Array.set(paddingUnit8Array, 0);
          recordUint8Array.set(payloadUint8Array, paddingUnit8Array.byteLength);

          const algorithm = {
            'name': 'AES-GCM',
            'tagLength': 128,
            'iv': encryptionKeys.nonce,
          };

          return crypto.subtle.encrypt(
            algorithm, encryptionKeys.contentEncryptionCryptoKey,
            recordUint8Array
          );
        })
        .then((encryptedPayloadArrayBuffer) => {
          return {
            cipherText: encryptedPayloadArrayBuffer,
            salt: window.uint8ArrayToBase64Url(salt),
            publicServerKey: window.uint8ArrayToBase64Url(
              exportedServerKeys.publicKey),
          };
        });
      });
    });
  }

  static generateServerKeys() {
    // 'true' is to make the keys extractable
    return crypto.subtle.generateKey({'name': 'ECDH', 'namedCurve': 'P-256'},
      true, ['deriveBits']);
  }

  _generateEncryptionKeys(subscription, salt, serverKeys) {
    return Promise.all([
      this._generatePRK(subscription, serverKeys),
      this._generateCEKInfo(subscription, serverKeys),
      this._generateNonceInfo(subscription, serverKeys),
    ])
    .then((results) => {
      const prk = results[0];
      const cekInfo = results[1];
      const nonceInfo = results[2];

      const cekHKDF = new HKDF(prk, salt);
      const nonceHKDF = new HKDF(prk, salt);
      return Promise.all([
        cekHKDF.generate(cekInfo, 16),
        nonceHKDF.generate(nonceInfo, 12),
      ]);
    })
    .then((results) => {
      return {
        contentEncryptionKey: results[0],
        nonce: results[1],
      };
    });
  }

  _generateContext(subscription, serverKeys) {
    return Promise.resolve()
    .then(() => {
      return window.arrayBuffersToCryptoKeys(subscription.getKey('p256dh'));
    })
    .then((keys) => {
      return keys.publicKey;
    })
    .then((clientPublicKey) => {
      return {
        clientPublicKey: clientPublicKey,
        serverPublicKey: serverKeys.publicKey,
      };
    })
    .then((keysAsCryptoKeys) => {
      return Promise.all([
        window.cryptoKeysToUint8Array(keysAsCryptoKeys.clientPublicKey),
        window.cryptoKeysToUint8Array(keysAsCryptoKeys.serverPublicKey),
      ])
      .then((keysAsUint8) => {
        return {
          clientPublicKey: keysAsUint8[0].publicKey,
          serverPublicKey: keysAsUint8[1].publicKey,
        };
      });
    })
    .then((keys) => {
      const utf8Encoder = new TextEncoder('utf-8');
      const labelUnit8Array = utf8Encoder.encode('P-256');
      const paddingUnit8Array = new Uint8Array(1).fill(0);

      const clientPublicKeyLengthUnit8Array = new Uint8Array(2);
      clientPublicKeyLengthUnit8Array[0] = 0x00;
      clientPublicKeyLengthUnit8Array[1] = keys.clientPublicKey.byteLength;

      const serverPublicKeyLengthBuffer = new Uint8Array(2);
      serverPublicKeyLengthBuffer[0] = 0x00;
      serverPublicKeyLengthBuffer[1] = keys.serverPublicKey.byteLength;

      return window.joinUint8Arrays([
        labelUnit8Array,
        paddingUnit8Array,
        clientPublicKeyLengthUnit8Array,
        keys.clientPublicKey,
        serverPublicKeyLengthBuffer,
        keys.serverPublicKey,
      ]);
    });
  }

  _generateCEKInfo(subscription, serverKeys) {
    return Promise.resolve()
    .then(() => {
      const utf8Encoder = new TextEncoder('utf-8');
      const contentEncoding8Array = utf8Encoder
        .encode('Content-Encoding: aesgcm');
      const paddingUnit8Array = new Uint8Array(1).fill(0);
      return this._generateContext(subscription, serverKeys)
      .then((contextBuffer) => {
        return window.joinUint8Arrays([
          contentEncoding8Array,
          paddingUnit8Array,
          contextBuffer,
        ]);
      });
    });
  }

  _generateNonceInfo(subscription, serverKeys) {
    return Promise.resolve()
    .then(() => {
      const utf8Encoder = new TextEncoder('utf-8');
      const contentEncoding8Array = utf8Encoder
        .encode('Content-Encoding: nonce');
      const paddingUnit8Array = new Uint8Array(1).fill(0);
      return this._generateContext(subscription, serverKeys)
      .then((contextBuffer) => {
        return window.joinUint8Arrays([
          contentEncoding8Array,
          paddingUnit8Array,
          contextBuffer,
        ]);
      });
    });
  }

  _generatePRK(subscription, serverKeys) {
    return this._getSharedSecret(subscription, serverKeys)
    .then((sharedSecret) => {
      const utf8Encoder = new TextEncoder('utf-8');
      const authInfoUint8Array = utf8Encoder
        .encode('Content-Encoding: auth\0');

      const hkdf = new HKDF(
        sharedSecret,
        subscription.getKey('auth'));
      return hkdf.generate(authInfoUint8Array, 32);
    });
  }

  _getSharedSecret(subscription, serverKeys) {
    return Promise.resolve()
    .then(() => {
      return window.arrayBuffersToCryptoKeys(subscription.getKey('p256dh'));
    })
    .then((keys) => {
      return keys.publicKey;
    })
    .then((publicKey) => {
      if (!(publicKey instanceof CryptoKey)) {
        throw new Error('The publicKey must be a CryptoKey.');
      }

      const algorithm = {
        'name': 'ECDH',
        'namedCurve': 'P-256',
        'public': publicKey,
      };

      return crypto.subtle.deriveBits(
        algorithm, serverKeys.privateKey, 256);
    });
  }
}

if (typeof window !== 'undefined') {
  window.gauntface = window.gauntface || {};
  window.gauntface.EncryptionHelperAESGCM = EncryptionHelperAESGCM;
}
class Ruleta {
  constructor(document, window, remote={}) {
    this.document = document;
    this.window = window;
    this.remote = remote;
    this.numbers = [0,2,14,35,23,4,16,33,21,6,18,31,19,8,12,29,25,10,27,'00',1,13,36,24,3,15,34,22,5,17,32,20,7,11,30,26,9,28];
    this.playerName = null;
    this.playerEmail = null;
    this.name = 'Guest';
    this.email = 'example@example.com';
    this.wheel = null;
    this.board = null;
    this.ballSpot = null;
    this.wheelDiv = null;
    this.gameDiv = null;
    this.audio = null;
  }
  initAll(parentNode) {
    let gameDiv = this.document.createElement('div');
    let boardDiv = this.document.createElement('div');
    let wheelDiv = this.document.createElement('div');

    gameDiv.appendChild(wheelDiv);
    gameDiv.appendChild(boardDiv);
    parentNode.appendChild(gameDiv);

    gameDiv.className = 'game';
    boardDiv.className = 'board';
    wheelDiv.className = 'wheel';

    this.wheel = this.initWheel(wheelDiv);
    this.board = this.initBoard(boardDiv);
    this.ballSpot = this.wheel[0];

    this.wheelDiv = wheelDiv;
    this.wheelDiv.onclick = _=>this.play();
    if (this.remote.playLocal) {
      this.remote.playLocal((playerName, playerEmail)=>{
        this.setPlayer(playerName, playerEmail);
        this.play();
      });
    }

    if (this.remote.betLocal) {
      this.remote.betLocal((tile, evt)=>this.board[tile][evt]());
    }

    this.gameDiv = gameDiv;

    this.board.bank.dataset.bet = 100;

    this.audio = this.initAudio();

    this.window.localStorage.top10 = this.window.localStorage.top10 || '[]';
  }

  initWheel(parent) {
    let numbers = this.numbers;
    let wheel = {};
    let prev, nextColor = 'black';
    for(let number of numbers){
      let node = this.document.createElement('div');
      let label = this.document.createElement('div');
      let color = 1*number === 0?'green':nextColor;
      node.className = 'number ' + color + ' ' + nextColor;
      nextColor = nextColor == 'black'?'red':'black';
      node.dataset.number = number;
      node.dataset.color = color;
      label.appendChild(this.document.createTextNode(number));
      label.className = 'label';
      prev = wheel[number] = {wheel: node, number, color, prev};
      node.appendChild(label);
      parent.appendChild(node);
      parent = node;
    }
    wheel[0].prev = prev;
    return wheel;
  }

  initBoard(parent) {
    let board = {};
    let table = this.document.createElement('table');
    let tr1 = this.document.createElement('tr');
    let tr2 = this.document.createElement('tr');
    let tr3 = this.document.createElement('tr');
    let tr4 = this.document.createElement('tr');
    let tr5 = this.document.createElement('tr');
    tr1.appendChild(this.wheel['00'].board = this.makeNumberTile(board, '00')).rowSpan = 2;
    tr3.appendChild(this.wheel['0'].board = this.makeNumberTile(board, '0'));
    for(let i=3;i<=36;i+=3) {
      let node1 = this.makeNumberTile(board, i);
      let node2 = this.makeNumberTile(board, i-1);
      let node3 = this.makeNumberTile(board, i-2);
      tr1.appendChild(node1);
      tr2.appendChild(node2);
      tr3.appendChild(node3);
    }
    let row1 = this.makeCustomTile(board, 'row1', '2 to 1', 3, 'green');
    let row2 = this.makeCustomTile(board, 'row2', '2 to 1', 3, 'green');
    let row3 = this.makeCustomTile(board, 'row3', '2 to 1', 3, 'green');
    tr1.appendChild(row1);
    tr2.appendChild(row2);
    tr3.appendChild(row3);
    let playerTile = tr4.appendChild(this.document.createElement('td'));
    playerTile.className = 'player';
    let player = playerTile.appendChild(document.createElement('div'))
    playerTile.rowSpan = 2;
    let playerName = player.appendChild(document.createElement('input'));
    let playerEmail = player.appendChild(document.createElement('input'));
    playerName.placeholder = 'name';
    playerEmail.placeholder = 'email';
    playerName.onchange = _=>{
      this.name = playerName.value;
    };
    playerEmail.onchange = _=>{
      this.email = playerEmail.value;
    };
    playerName.value = this.name;
    playerEmail.value = this.email;
    this.playerName = playerName;
    this.playerEmail = playerEmail;
    tr4.appendChild(this.makeCustomTile(board, '1st12','1st 12', 3, 'green')).colSpan = 4;
    tr4.appendChild(this.makeCustomTile(board, '2nd12','2nd 12', 3, 'green')).colSpan = 4;
    tr4.appendChild(this.makeCustomTile(board, '3rd12','3rd 12', 3, 'green')).colSpan = 4;
    tr5.appendChild(this.makeCustomTile(board, '1to18','1 - 18', 3, 'green')).colSpan = 2;
    tr5.appendChild(this.makeCustomTile(board, 'even','EVEN', 2, 'green')).colSpan = 2;
    tr5.appendChild(this.makeCustomTile(board, 'red','\xA0', 2, 'red')).colSpan = 2;
    tr5.appendChild(this.makeCustomTile(board, 'black','\xA0', 2, 'black')).colSpan = 2;
    tr5.appendChild(this.makeCustomTile(board, 'odd','ODD', 2, 'green')).colSpan = 2;
    tr5.appendChild(this.makeCustomTile(board, '19to36','19 - 36', 3, 'green')).colSpan = 2;
    tr4.appendChild(this.makeCustomTile(board, 'bank','balance', 1, 'green')).rowSpan = 2;
    table.appendChild(tr1);
    table.appendChild(tr2);
    table.appendChild(tr3);
    table.appendChild(tr4);
    table.appendChild(tr5);
    parent.appendChild(table);
    return board;
  }

  makeNumberTile(board, number) {
    let tile = this.makeCustomTile(board, number, number, 36, this.wheel[number].color, 'circled');
    this.wheel[number].payout = {
      red: this.wheel[number].color == 'red',
      black: this.wheel[number].color == 'black',
      'row1': number%3 == 0 && number != 0,
      'row2': number%3 == 2,
      'row3': number%3 == 1,
      '1st12': number >= 1 && number < 13,
      '2nd12': number > 12 && number < 25,
      '3rd12': number > 24 && number <= 36,
      '1to18': number >= 1 && number <= 18,
      '19to36': number >= 19 && number <= 36,
      'even': number%2 == 0 && number != 0,
      'odd': number%2 == 1,
      'bank': true,
      [number]: true,
    };
    return tile;
  }

  makeCustomTile(board, id, text, payout, color, style='') {
    let tile = this.document.createElement('td');
    tile.dataset.id = id;
    tile.dataset.payout = payout;
    tile.dataset.bet = 0;
    tile.onclick = e=> {
      if (board.bank.dataset.bet > 0) {
        tile.dataset.bet++;
        board.bank.dataset.bet--;
        if (this.remote.betRemote) {
          this.remote.betRemote(id, 'onclick');
        }
      }
    };
    tile.onauxclick = e=> {
      if (tile.dataset.bet > 0) {
        tile.dataset.bet--;
        board.bank.dataset.bet++;
        if (this.remote.betRemote) {
          this.remote.betRemote(id, 'onauxclick');
        }
      }
    };
    tile.oncontextmenu = e=> false;
    tile.className = 'tile';
    let label = this.document.createElement('div');
    label.className = 'label ' + style + ' ' + color;
    label.appendChild(this.document.createTextNode(text));
    tile.appendChild(label);
    board[id] = tile;
    return tile;
  }

  initAudio() {
    let context = new AudioContext;
    let o = context.createOscillator();
    let g = context.createGain();
    o.connect(g);
    g.connect(context.destination);
    o.type = 'triangle';
    o.frequency.value = 87.31;
    o.start(0);
    g.gain.value = 1e-5;
    return {context, g, o};
  }

  async getTop10(commit) {
    if (this.remote.getTop10Remote) {
      return this.remote.getTop10Remote();
    }
    let top10 = JSON.parse(this.window.localStorage.top10);
    top10.push({
      name: this.name,
      email: this.email,
      score: this.board.bank.dataset.bet
    });
    top10 = top10.sort((a,b)=>b.score-a.score).slice(0, 10);
    if (commit) {
      this.window.localStorage.top10 = JSON.stringify(top10);
    } else {
      top10.forEach(e=>e.email=e.email.replace(/(.{4}).*@(.*)(?:add-some-privacy){0}/g,'$1...@$2'));
    }
    return top10;
  }

  setPlayer(name, email) {
    this.playerName.value = this.name = name;
    this.playerEmail.value = this.email = email;
  }

  spinWheelLocal(end) {
    return new Promise(res=>{
      let finishedSpinning = false, stopMovingBall = false;
      let ballSpot = this.ballSpot;
      let moveBall = ()=>{
        ballSpot.wheel.dataset.ball = false;
        ballSpot = ballSpot.prev;
        ballSpot.wheel.dataset.ball = true;
        stopMovingBall = finishedSpinning && String(ballSpot.number) == String(end);
        if (this.remote.spinWheelMoveBallLocal) {
          let rotate = this.window.getComputedStyle(this.wheelDiv).rotate;
          let number = ballSpot.number;
          this.remote.spinWheelMoveBallLocal(number, rotate, !stopMovingBall);
        }
        if (!stopMovingBall) {
          this.window.requestAnimationFrame(moveBall);
        } else {
          res(this.ballSpot = ballSpot);
        }
      };
      moveBall();
      this.gameDiv.dataset.spin = false;
      this.window.requestAnimationFrame(_=>{
        this.gameDiv.dataset.spin = true;
      });
      this.window.setTimeout(_=>{
        finishedSpinning = true;
      }, 8e3);
    });
  }

  async spinWheelRemote() {
    this.gameDiv.dataset.spin = 'fake';
    if (this.remote.spinWheelMoveBallRemote) {
      let rotate, number, promise = this.remote.spinWheelMoveBallRemote();
      while (promise) {
        let {rotate, number, next} = await promise;
        let oldBall = this.ballSpot;
        let ballSpot = this.ballSpot = this.wheel[number];
        this.wheelDiv.style.rotate = rotate;
        oldBall.wheel.dataset.ball = false;
        ballSpot.wheel.dataset.ball = true;
        promise = next;
      }
    }
    let number = await this.remote.spinWheelRemote();
    this.ballSpot = this.wheel[number];
    return this.ballSpot;
  }

  async spinWheel() {
    let sound = this.window.setInterval(_=>{
      this.audio.g.gain.exponentialRampToValueAtTime(1, this.audio.context.currentTime);
      this.audio.g.gain.exponentialRampToValueAtTime(1e-5, this.audio.context.currentTime + 1);
    }, 100);
    this.window.setTimeout(_=>{
      this.window.clearInterval(sound);
    }, 8e3);
    if (this.remote.spinWheelRemote) {
      return this.spinWheelRemote();
    }
    let rnd = await this.getRandom(this.numbers.length);
    return this.spinWheelLocal(this.numbers[rnd]);
  }

  async getRandom(max) {
    return Math.floor(max*crypto.getRandomValues(new Uint8Array(1))[0]/0xFF);
  }

  async playLocal() {
    let board = {};
    for (let tile in this.board) {
      board[tile] = {
        bet: this.board[tile].dataset.bet,
        payout: this.board[tile].dataset.payout,
      };
    }
    let spot = await this.spinWheel();
    let results = {};
    for (let tile in board) {
      results[tile] = {};
      if (spot.payout[tile]) {
        results[tile].bet = board[tile].bet * board[tile].payout;
        results[tile].lost = false;
      } else {
        results[tile].lost = this.board[tile].dataset.bet != 0;
        results[tile].bet = 0;
      }
    }
    if (this.remote.spinWheelLocal) {
      let top10 = await this.getTop10(false);
      this.remote.spinWheelLocal({
        number: spot.number,
        results,
        top10
      });
    }
    return results;
  }
  async playRemote() {
    let results = this.remote.playRemote({
      name: this.name,
      email: this.email
    });
    await this.spinWheel();
    return await results;
  }
  async play() {
    let results;
    if (this.remote.playRemote) {
      results = await this.playRemote();
    } else {
      results = await this.playLocal();
    }
    for (let tile in results) {
      this.board[tile].dataset.bet = results[tile].bet;
      this.board[tile].dataset.lost = results[tile].lost;
    }
    let top10 = await this.getTop10(true);
    this.window.top10.innerHTML = `<ol>${top10.map(p=>`<li>${p.name.link(`mailto:${p.email}`)}: ${p.score}`).join('')}</ol>`;
    return results;
  }
}

class RuletaLocal {
  constructor(messageSender, messageListener) {
    this.messageSender = messageSender;
    this.messageListener = messageListener;
  }
  spinWheelMoveBallLocal(number, rotate, next) {
    this.messageSender.send({
      'type': 'spinWheelMoveBall',
      'value': {
        'number': number, 'rotate': rotate, 'next': next}
    });
  }
  spinWheelLocal(obj) {
    this.messageSender.send({
      'type': 'spinWheel',
      'value': obj
    });
  }
  playLocal(fn) {
    this.messageListener.listen(msg=>{
      if(msg['type']=='play'){
        fn(msg['value']['name'], msg['value']['email']);
      }
    });
  }
  betLocal(fn) {
    this.messageListener.listen(msg=>{
      if(msg['type']=='bet'){
        fn(msg['value']['tile'], msg['value']['event']);
      }
    });
  }
}

class RuletaRemota {
  constructor(messageSender, messageListener) {
    this.messageSender = messageSender;
    this.messageListener = messageListener;
    this.nextSpin = new Promise(this.resolver.bind(this, 'spinWheelMoveBall'));
    this.result = null;
  }
  resolver(type, res, rej) {
    this.messageListener.listen(msg=>{
      if (msg['type']==type) {
        res(msg['value']);
        return true;
      }
    });
  }
  async spinWheelMoveBallRemote(nextSpin=null) {
    let spin = nextSpin || await this.nextSpin;
    if (spin.next) {
      spin.next =
        new Promise(this.resolver.bind(this, 'spinWheelMoveBall'))
        .then(s=>this.spinWheelMoveBallRemote(s));
    }
    return spin;
  }
  async spinWheelRemote() {
    return (await this.result)['number'];
  }
  async playRemote(player) {
    this.result = new Promise(this.resolver.bind(this, 'spinWheel'));
    this.messageSender.send({
      'type': 'play',
      'value': player
    });
    return (await this.result)['results'];
  }
  async betRemote(tile, event) {
    this.messageSender.send({
      'type': 'bet',
      'value': {'tile': tile, 'event': event}
    });
  }
  async getTop10Remote() {
    return (await this.result)['top10'];
  }
}

class MessageListener {
  constructor() {
    this.fns = [];
  }
  handle(msg) {
    msg = JSON.parse(msg);
    this.fns = this.fns.filter(fn=>{
      try {
        return !fn(msg);
      } catch(e) {}
      return true;
    });
  }
  listen(fn) {
    this.fns.push(fn);
  }
}

class MessageSenderX {
  constructor() {
    this.pending = [];
    this.sendFunction = null;
  }
  send(msg) {
    msg = JSON.stringify(msg);
    if (this.sendFunction) {
      return this.sendFunction(msg);
    }
    this.pending.push(msg);
  }
  setSender(fn){
    this.sendFunction = fn;
    for(msg of this.pending) {
      this.send(msg);
    }
    this.pending = [];
  }
}
class Comms {
  constructor(window) {
    this.key = {
      'x': 'V7QlgXmOiS_qYiII-pqvyuBBAr8e0cWYMYmsXxB41pA',
      'y': 'mwtxIkIZyFF0QIBnnMx3yXDOE2eS-7HcmG6260aPJQs',
      'd': 'fMJiRf3caw57MXGrFn-YuVcdjfyne0Y6rxKsvKK-1DI'
    };
    this.key.serverKey = new Uint8Array((
      '\x04' +
      this.base64decode(this.key.x) +
      this.base64decode(this.key.y)).split('').map(c=>c.charCodeAt()));
    this.key.encodedPublicKey = this.base64encode(
      String.fromCharCode.apply(null, this.key.serverKey));
    this.window = window;
    window.gauntface.CONSTANTS = {
      APPLICATION_KEYS: {
        publicKey: this.key.encodedPublicKey,
        privateKey: this.key.d
      }
    };
    this.workerUrl = 'worker.js';
    this.proxy = req => fetch(req.url, req);
    this.window = window;
    this.pushMessageFns = [];
    this.rtcConnection = null;
    this.localAnswer = null;
    this.channel = null;
    this.offer = null;
    this.cryptoHelper = null;
    this.pushManager = null;
    this.subscription = null;
  }
  async initPush() {
    let reg = await this.window.navigator.serviceWorker.getRegistration();
    if (!reg) {
      await this.window.navigator.serviceWorker.register(this.workerUrl);
      this.window.location.reload();
    }
    this.pushManager = reg.pushManager;
    this.cryptoHelper = new EncryptionHelperAESGCM();
    let chan = new MessageChannel;
    reg.active.postMessage('push', [chan.port1]);
    chan.port2.onmessage = e => {
      this.distributePushMessages(e.data);
    };
  }
  async initRTC() {
    let config = {
      'iceServers': [
        // STUN
        {'url':'stun:stun.l.google.com:19302'},
        {'url':'stun:stun1.l.google.com:19302'},
        {'url':'stun:stun2.l.google.com:19302'},
        {'url':'stun:stun3.l.google.com:19302'},
        {'url':'stun:stun4.l.google.com:19302'},
        // TURN
        {
          'url': 'turn:35.195.85.49:3478',
          'credential': 'ekXUNWC7GT2aOzP77H',
          'username': 'gctf2017',
          'hint': 'this is not part of the challenge'
        }
      ]
    };
    this.rtcConnection = new RTCPeerConnection(config);
  }
  async init() {
    return Promise.all([this.initPush(), this.initRTC()]);
  }
  // push
  async subscribePush() {
    return this.subscription = await this.pushManager.subscribe({
      'userVisibleOnly': true,
      'applicationServerKey': this.key.serverKey
    });
  }
  async sendPushMessage(subscription, data) {
    let req = await this.cryptoHelper.getRequestDetails(
      this.fixSubscription(subscription),
      JSON.stringify(data));
    req.method = 'post';
    req.url = req.endpoint;
    return this.proxy(req);
  }
  receivePushMessages(fn) {
    this.pushMessageFns.push(fn);
  }
  async distributePushMessages(msg) {
    this.pushMessageFns.forEach(fn=>{
      try {fn(msg);} catch(e) {Promise.reject(e);}
    });
  }
  fixSubscription(subscription) {
    subscription.getKey = key=>new Uint8Array(
      this.base64decode(subscription.keys[key])
      .split('').map(c=>c.charCodeAt()));
    return subscription;
  }
  // rtc
  async createRTCChannel(candidateCallback) {
    this.channel = this.rtcConnection.createDataChannel('sendDataChannel', null);
    this.offer = await this.rtcConnection.createOffer();
    await this.rtcConnection.setLocalDescription(this.offer);
    this.rtcConnection.onicecandidate = e=> {
      e.candidate && candidateCallback(e.candidate);
    };
    return {localOffer: this.offer, channel: this.channel};
  }
  async acceptRTCChannel(remoteAnswer) {
    await this.rtcConnection.setRemoteDescription(remoteAnswer);
  }
  async openRTCChannel(remoteOffer, candidateCallback) {
    await this.rtcConnection.setRemoteDescription(remoteOffer);
    this.rtcConnection.onicecandidate = e=> {
      e.candidate && candidateCallback(e.candidate);
    };
    let channelPromise = new Promise(res=>{
      this.rtcConnection.ondatachannel = e=> {
        e.channel && res(this.channel = e.channel);
      };
    });
    this.localAnswer = await this.rtcConnection.createAnswer();
    await this.rtcConnection.setLocalDescription(this.localAnswer);
    return {
      localAnswer: this.localAnswer,
      channelPromise
    };
  }
  addCandidate(remoteCandidate) {
    this.rtcConnection.addIceCandidate(remoteCandidate);
  }
  base64encode(str){
    return btoa(str).replace(/[+]/g,'-').replace(/[/]/g,'_');
  }

  base64decode(str){
    return atob(str.replace(/-/g,'+').replace(/_/g,'/'));
  }
}

class GameHosting {
  constructor(window) {
    this.window = window;
    this.serverSubscription = null;
    this.clientSubscription = null;
    this.clientOffer = null;
    this.channel = null;
    this.comms = null;
  }
  async init(acceptCallback) {
    this.comms = new Comms(this.window);
    await this.comms.init();
    this.serverSubscription = await this.comms.subscribePush();
    let pendingCandidates = [];
    let hasOffer = false;
    this.comms.receivePushMessages(msg=>{
      if (msg.type == 'clientCandidate') {
        pendingCandidates.push(msg['clientCandidate']);
        if (hasOffer) {
          this.comms.addCandidate(msg['clientCandidate']);
        }
      }
      if (msg.type == 'clientOffer') {
        hasOffer = true;
        acceptCallback(msg, pendingCandidates);
      }
    });
  }

  setClient(clientSubscription, clientOffer) {
    this.clientSubscription = clientSubscription;
    this.clientOffer = clientOffer;
  }

  async getChannel(pendingCandidates) {
    let {localAnswer, channelPromise} = await this.comms.openRTCChannel(
      this.clientOffer, c=>this.sendCandidate(c));
    for (let clientCandidate of pendingCandidates) {
      this.comms.addCandidate(clientCandidate);
    }
    this.comms.sendPushMessage(this.clientSubscription, {
      'type': 'serverAnswer',
      'serverAnswer': localAnswer
    });
    return this.channel = await channelPromise;
  }

  sendCandidate(serverCandidate) {
    this.comms.sendPushMessage(this.clientSubscription, {
      'type': 'serverCandidate',
      'serverCandidate': serverCandidate
    });
  }
}

class GameClient {
  constructor(window) {
    this.window = window;
    this.serverSubscription = null;
    this.clientSubscription = null;
    this.channelPromise = null;
    this.comms = null;
  }

  async init(serverSubscription) {
    this.comms = new Comms(this.window);
    await this.comms.init();
    this.serverSubscription = serverSubscription;
    this.clientSubscription = await this.comms.subscribePush();
    let {localOffer, channel} = await this.comms.createRTCChannel(c=>this.sendCandidate(c));
    this.channelPromise = new Promise(res=>{
      channel.onopen = e=> res(channel);
    })
    this.comms.receivePushMessages(msg=>{
      if (msg.type == 'serverAnswer') {
        this.comms.acceptRTCChannel(msg.serverAnswer);
      }
      if (msg.type == 'serverCandidate') {
        this.comms.addCandidate(msg.serverCandidate);
      }
    });
    this.comms.sendPushMessage(serverSubscription, {
      'type': 'clientOffer',
      'clientSubscription': this.clientSubscription,
      'clientOffer': localOffer
    });
  }

  async getChannel() {
    let channel = await this.channelPromise;
    return channel;
  }

  sendCandidate(clientCandidate) {
    this.comms.sendPushMessage(this.serverSubscription, {
      'type': 'clientCandidate',
      'clientCandidate': clientCandidate
    });
  }
}
class Glue {
  constructor(window, document) {
    this.window = window;
    this.document = document;
    this.client = null;
    this.server = null;
  }
  async init() {
    let hash = this.window.location.hash.substr(1);
    if (!hash) {
      return this.initServer();
    } else {
      let init = this.decode(hash);
      if ('serverSubscription' in init) {
        return this.initClient(init['serverSubscription']);
      } else {
        console.error('Invalid init data', init);
        this.window.location.hash = '';
        this.window.location.reload();
      }
    }
  }
  encode(msg) {
    return encodeURIComponent(btoa(JSON.stringify(msg)));
  }
  decode(str) {
    return JSON.parse(atob(decodeURIComponent(str)));
  }
  async initServer() {
    table.innerHTML = 'Waiting for player..';
    let server = new GameHosting(this.window);
    let refreshTimeout = this.window.setTimeout(_=>{
      location.reload();
    }, 30e3);
    // Listen for connections
    await server.init(async (msg, pendingCandidates)=>{
      if (server.clientOffer) {
        location.reload();
        return;
      }
      this.window.clearTimeout(refreshTimeout);
      server.setClient(msg['clientSubscription'], msg['clientOffer']);
      let channel = await server.getChannel(pendingCandidates);
      channel.onclose = _=>this.window.location.reload();
      table.innerHTML = '';
      let sender = new MessageSenderX();
      let listener = new MessageListener();
      sender.setSender(msg=>channel.send(msg));
      channel.onmessage = e=>listener.handle(e.data);
      this.server = await (new Ruleta(
        this.window.document,
        this.window,
        new RuletaLocal(sender, listener))).initAll(table);
    });
    let inviteUrl = `${
      location.origin + location.pathname
    }?join#${
      this.encode({
        'serverSubscription': server.serverSubscription
      })
    }`;
    console.log('Invite URL', inviteUrl);
    inviteLink.href = `mailto:?subject=Invite&body=${escape(`Let's play Flag Roullete!\n\n${inviteUrl}`)}`;
    inviteLink.innerHTML = 'email invite link';
  }
  async initClient(serverSubscription) {
    table.innerHTML = 'Connecting to game server..';
    let client = new GameClient(this.window);
    await client.init(serverSubscription);;
    let channel = await client.getChannel();
    channel.onclose = _=>this.window.location.reload();
    table.innerHTML = ''
    let sender = new MessageSenderX();
    let listener = new MessageListener();
    sender.setSender(msg=>channel.send(msg));
    channel.onmessage = e=>listener.handle(e.data);
    this.client = await new Ruleta(
      this.window.document,
      this.window,
      new RuletaRemota(sender, listener)).initAll(table);
  }
}

game_ = (new Glue(window, document)).init();

