// Copyright 2017, Google, Inc.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

'use strict';

const Datastore = require('@google-cloud/datastore');
const config = require('../config');

const ds = Datastore({
  projectId: config.get('GCLOUD_PROJECT'),
  namespace: 'books'
});
const kind = 'User';


// Translates from Datastore's entity format to
// the format expected by the application.
//
// Datastore format:
//   {
//     key: [kind, id],
//     data: {
//       property: value
//     }
//   }
//
// Application format:
//   {
//     id: id,
//     property: value
//   }
function fromDatastore (obj) {
  obj.id = obj[Datastore.KEY].name;
  return obj;
}

// Translates from the application's format to the datastore's
// extended entity property format. It also handles marking any
// specified properties as non-indexed. Does not translate the key.
//
// Application format:
//   {
//     id: id,
//     property: value,
//     unindexedProperty: value
//   }
//
// Datastore extended format:
//   [
//     {
//       name: property,
//       value: value
//     },
//     {
//       name: unindexedProperty,
//       value: value,
//       excludeFromIndexes: true
//     }
//   ]
function toDatastore (obj, nonIndexed) {
  nonIndexed = nonIndexed || [];
  let results = [];
  Object.keys(obj).forEach((k) => {
    if (obj[k] === undefined) {
      return;
    }
    results.push({
      name: k,
      value: obj[k],
      excludeFromIndexes: nonIndexed.indexOf(k) !== -1
    });
  });
  return results;
}

function update (id, data, cb) {
  let key;
  if (id) {
    key = ds.key([kind, id.toString()]);
  } else {
    key = ds.key(kind);
  }

  const entity = {
    key: key,
    data: toDatastore(data)
  };

  ds.save(
    entity,
    (err) => {
      data.id = entity.key.name;
      cb(err, err ? null : data);
    }
  );
}


function get (id, cb) {
  const key = ds.key([kind, id.toString()]);
  return new Promise((resolve, reject) => {
    ds.get(key, (err, entity) => {
      if (!err && !entity) {
        resolve(null);
        return;
      }
      if (err) {
        reject(err);
        return;
      }
      resolve(fromDatastore(entity));
    });
  });
}


module.exports = {
  get,
  update
};
