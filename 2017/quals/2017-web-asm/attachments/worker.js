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
 * @param {!MessageEvent} e
 */
self['onmessage'] = function(e) {
  _stdin = [].shift.bind(e.data['stdin'].slice(0));
  _stdout = _stderr = function(msg) {
    if (location.search.indexOf('debug') > -1) {
      console.log(msg);
    }
  };
  var counters = {'cycles': 0};
  postMessage({
    'answer': execute(e.data['program'], counters),
    'test': e.data['stdin'],
    'counters': counters,
  });
};
