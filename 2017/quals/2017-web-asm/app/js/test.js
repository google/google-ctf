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



var c = 0;
var testcases = _testcases;

/**
 * @param {string} message
 */
_showUser = function (message) {
  alert(message);
};

/**
 * @param {string} message
 */
function showUser(message) {
  self['_showUser'](message);
}

/**
 * @param {{test:string}} data
 * @extends Error
 * @constructor
 */
function TestCaseError(data) {
  Error.call(this, this.message = 'Wrong answer on test ' + data.test);
}
TestCaseError.prototype = Error.prototype;

/**
 * @param {string} script
 * @constructor
 */
var TestWorker =
    (!location.href.match(/noworker/) && self['Worker']) || function(script) {
      var iframe = document.body.appendChild(document.createElement('iframe'));
      iframe.sandbox = 'allow-scripts';
      iframe.srcdoc = `
<meta http-equiv=content-security-policy content="default-src ${location.origin}/js/ 'unsafe-eval' 'unsafe-inline'">
<script>function postMessage(d){parent.postMessage(d,'*')}</script>
<script src="${script}"></script>`;
      var me = this;
      var messages = [];
      iframe.onload = function() {
        me.postMessage = function(msg, trs) {
          iframe.contentWindow.postMessage(msg, '*', trs);
        };
        messages.forEach(function(args) {
          me.postMessage.apply(me, args);
        });
      };
      window.addEventListener('message', function(e) {
        if (e.source == iframe.contentWindow) {
          try {
            me.onmessage(e);
          } catch (e) {
          }
        }
      }, false);
      this.postMessage = function(msg, trs) {
        messages.push([msg, trs]);
      };
      this.terminate = function() {
        if (iframe.parentNode) {
          iframe.parentNode.removeChild(iframe);
        }
      };
    };

/**
 * @param {string} challenge
 * @param {!Uint8Array} asm
 * @param {string} debug
 * @return {!IThenable}
 */
function runTests(challenge, asm, debug) {
  debug = debug || location.href.match(/debug/);
  history.replaceState(null, null, '/');
  console.log('Starting tests..');
  var tests = testcases[challenge];
  return Promise
      .all(tests.map(function(test) {
        var worker =
            new TestWorker('js/worker.min.js?' + debug);
        var program = asm.slice(0);
        worker.postMessage(
            {
              'stdin': test[0],
              'program': program,
            },
            [program]);
        return new Promise(function(resolve, reject) {
          worker.onerror = function(e) {
            reject(e);
          };
          worker.onmessage = function(e) {
            if (e.data['answer'] == test[1]) {
              resolve(e.data);
            } else {
              reject(new TestCaseError(e.data));
            }
            worker.terminate();
          };
        });
      }))
      .then(function(results) {
        showUser('Your code is correct!');
        var cycles = results.reduce(function(acc, result) {
          return acc + result['counters']['cycles'];
        }, 0);
        console.log(cycles, asm.byteLength);
        if (cycles < 20 * tests.length) {
          if (asm.byteLength < 400) {
            showUser(
                'Your answers:' +
                results
                    .map(function(result) {
                      return result['answer'];
                    })
                    .join());
            return true;
          } else {
            showUser('Well done! Now make the code smaller.');
          }
        } else {
          showUser('Well done! Now make the code faster.');
        }
      })
      .catch(function(error) {
        if (debug) {
          console.error(error);
        }
        showUser('Got one or more invalid test cases.');
      });
}

_runTests = runTests;
