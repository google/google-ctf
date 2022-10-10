/**
 * Copyright 2022 Google LLC
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

const express = require("express");
const fs = require('fs');
const {VM, VMScript} = require("vm2");
const bot = require('./bot.js');
const app = express();
const Recaptcha = require('express-recaptcha').RecaptchaV2;
const recaptcha = new Recaptcha(process.env.RECAPTCHA_KEY, process.env.RECAPTCHA_SECRET);

const CHALL_URL = process.env.CHALL_URL;

app.use(express.static('public'))
app.use(express.urlencoded({extended:false}));

process.on('uncaughtException', (err, origin) => {
    console.error(err, 'Uncaught exception', origin);
});

const script = new VMScript(fs.readFileSync('./shoplib.mjs').toString().replaceAll('export ','') + `
sendOrder(cart, orders)
`);

app.get('/', async (req,res) => {
    fs.readFile('index.html', function(err, data) {
        res.writeHead(200, {'Content-Type': 'text/html'});
        res.write(data);
        return res.end();
    });
});

app.post('/order', recaptcha.middleware.verify, async (req,res)=>{
    req.setTimeout(1000);
    
    if (req.recaptcha.error && process.env.NODE_ENV != "dev") {
        res.writeHead(400, {'Content-Type': 'text/html'});
        return await res.end("invalid captcha");
    }

    if (!req.body.cart) {
        res.writeHead(400, {'Content-Type': 'text/html'});
        return await res.end("bad request")
    }

    // TODO: Group orders by zip code
    let orders = [];
    let cart = req.body.cart;
    let vm = new VM({sandbox: {orders, cart}});

    let result = await vm.run(script);

    orders = new Buffer.from(JSON.stringify(orders)).toString('base64');

    let url = '/order#' + orders;
    
    bot.visit(CHALL_URL + url);

    res.redirect(url);
});

app.get('/order', async (req,res) => {
    fs.readFile('order.html', function(err, data) {
        res.writeHead(200, {'Content-Type': 'text/html'});
        res.write(data);
        return res.end();
    });
});


const PORT = process.env.PORT || 1337;

app.listen(PORT, ()=>{
    console.log(`The app is listening on localhost:${PORT}`);
});
