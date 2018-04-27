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



//Lets require/import the HTTP module
const pubsub = require('@google-cloud/pubsub')();
const http = require('http');
const dispatcher = require('httpdispatcher');
const fs = require('fs');
const recaptcha = require('express-recaptcha');
const blog = require('./blog');

//Lets define a port we want to listen to
const PORT = process.env.PORT || 8080;

//Lets use our dispatcher
function handleRequest(request, response){
    try {
        //Disptach
        var method = request.method.toLowerCase();
        if (method != 'get' && method != 'post') {
            response.writeHead(405, {'Connection': 'close'});
            response.end();
            return;
        }

        dispatcher.dispatch(request, response);
    } catch(err) {
        console.log(err);
        //throw err;
    }
}

recaptcha.init('unused', process.env.RECAPTCHA_PRIVKEY);
process.env.RECAPTCHA_PRIVKEY= 'deleted'

//For all your static (js/css/images/etc.) set the directory name (relative path).
dispatcher.setStatic('static');
dispatcher.setStaticDirname('.');

//A sample GET request
dispatcher.onGet("/", function(req, res) {
    res.writeHead(200, {'Content-Type': 'text/html'});
    fs.readFile('static/pages/index.html', function(err, data) {
      if (err) throw err;
      res.end(data);
    });
});

dispatcher.beforeFilter("/reply", function(req, res, chain) {
    req.body = req.params;
    recaptcha.verify(req, function(error) {
        if(!error) {
            chain.next(req, res, chain);
        } else {
            res.writeHead(403);
            res.end('Wrong captcha.');
        }
    });
});

//A sample POST request
dispatcher.onPost("/reply", function(req, res) {

    if (req.params.comment && blog.check_comment(req.params.comment)) {
        console.log(req.params.comment);
        blog.insert_comment(req.params.comment).then((id) => {
            res.writeHead(200, {'Content-Type': 'text/html', 'X-XSS-Protection': '0'});
            fs.readFile('static/pages/valid.html', 'utf-8', function(err, data) {
                if (err) throw err;
                res.end(data.replace('$comment$', id)); // Templates not invented yet...

                var topic = pubsub.topic('xss');
                var comment_url = `https://${process.env.GAE_SERVICE}-dot-${process.env.GCLOUD_PROJECT}.appspot.com/comment?id=${id}`;
                topic.publish({service: 'geokitties',
                    url: comment_url});
            });
        });
    } else {
        res.writeHead(403, {'Content-Type': 'text/html'});
        fs.readFile('static/pages/invalid.html', function(err, data) {
            if (err) throw err;
            res.end(data);
        });
    }
});

dispatcher.onGet("/comment", function(req, res) {
    var post_id = req.params.id || '';

    if (!post_id) {
        res.writeHead(404);
        res.end();
    } else {
        blog.get_comment(post_id).then((result) => {
            res.writeHead(200, {'Content-Type': 'text/html'});
            if (result.viewed)
                res.end('Comment already validated.');
            else
                res.end(result.content);
            if (req.headers['user-agent'] && req.headers['user-agent'].indexOf('Headless') !== -1)
                blog.set_comment_viewed(post_id);
        }, () => {
            res.writeHead(404);
            res.end();
        }).catch((err) => {
            console.log(err);
            res.writeHead(500);
            res.end();
        });
    }
});

dispatcher.beforeFilter(/\//, function(req, res, chain) { //any url
    var filter = /dog|\.\.\/|passwd|select|union|insert|update|script|from|where|"|'/ig

    if (filter.test(req.url))
    {
        req.url = req.url.replace(filter, '');
        res.setHeader('WAF-Debug', new Buffer(req.url).toString('base64'));
    } else {
        res.setHeader('WAF-Debug', 'OK');
    }

    chain.next(req, res, chain);
});



//Create a server
var server = http.createServer(handleRequest);

//Lets start our server
server.listen(PORT, function() {
    //Callback triggered when server is successfully listening. Hurray!
    console.log("Server listening...");
});

