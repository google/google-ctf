/**
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

const {CloudTasksClient} = require('@google-cloud/tasks');
const DOMAINS = {
  'pasteurize.web.ctfcompetition.com': {
      public: 'https://pasteurize.web.ctfcompetition.com',
      private: 'https://littlethings.web.ctfcompetition.com'
  },
  'littlethings.web.ctfcompetition.com': {
      public: 'https://pasteurize.web.ctfcompetition.com',
      private: 'https://littlethings.web.ctfcompetition.com'
  },
}

function visit(id, req){
    const client = new CloudTasksClient();
    const parent = client.queuePath('instance-id','instance-region','xss');

    const note_url = `${req.domains.public}/${id}`;

    /* This only ensures that TJMike is logged into All the little things challenge
     and is not relevant to Pasteurize */
    const url = `${req.domains.private}/login?redir=${encodeURIComponent(note_url)}`;

    console.log(url);

    
    const task = {
      appEngineHttpRequest: {
        httpMethod: 'POST',
        relativeUri: '/submit',
        appEngineRouting: {
          service: 'uxssbot'
        },
        headers: {
         "Content-Type": 'application/x-www-form-urlencoded'
        },
        body: Buffer.from(`service=littlethings&url=${encodeURIComponent(url)}`)
      },
    };
 
    const request = {
      parent: parent,
      task: task,
    };
  
    client.createTask(request);
}

const sleep = d => new Promise(r => setTimeout(r, d));

/* enable caching on specific endpoints */
const cache_mw = (req, res, next) => {
    res.setHeader('Cache-Control', 'max-age=300');
    next();
  }

const domains_mw =  (req, res, next) => {
    const host = req.hostname;
    if (!DOMAINS.hasOwnProperty(host)) {
      return res.status(500).send("Something wrong with the host!");
    }
    /* 
     * domains.public -> pasteurize
     * domains.private -> littlethings
     */
    req.domains = DOMAINS[host];
    next();
  }

module.exports = {
    visit,
    sleep,
    cache_mw,
    domains_mw,
};