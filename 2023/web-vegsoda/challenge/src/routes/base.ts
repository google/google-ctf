/**
 * Copyright 2023 Google LLC
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

// @ts-ignore  
import { Router, Context, Status } from 'https://deno.land/x/oak/mod.ts';
// @ts-ignore  
import * as bcrypt from "https://deno.land/x/bcrypt/mod.ts";

import { visit } from '../utils/bot.ts';
import User from '../models/classes/User.ts';
import Soda from '../models/classes/Soda.ts';
import { AppState } from '../utils/session.ts';

const router = new Router<AppState>();

router.get('/', async (ctx: Context) => {
    var username = await ctx.state.session.get('username');
    if (username){
        ctx.response.redirect("/profile");
        return;
    }
    const csrf = await ctx.state.session.get("csrf");
    ctx.render("./views/home.ejs", {data:{csrf_token: csrf}});
    return;
});

/* ==================== REGISTER // LOGIN ==================== */
router.post('/register', async (ctx: Context) => {
    try {
        var username = await ctx.state.session.get('username');
        if (username){
            throw Error("You're already logged in!");
        }
        const u = await ctx.request.body({ type: "json" }).value;
        if (!/^[A-Za-z0-9]{1,20}$/.test(u.username)) {
            throw Error("Invalid username");
        }
        const id = crypto.randomUUID();
        const admin = await ctx.state.db.return_admin();
        const hash = await bcrypt.hash(u.password);

        const rows = await ctx.state.db.select_from_db("users", "username", u.username);
       
        if (rows.length === 0){
            await ctx.state.db.insert_stan_user(id, u.username, hash);
            //Default soda
            const soda = Soda.getSoda("Carrot", admin["username"], "Hello! Welcome to the veggie soda community :D");
            const user = new User(u.username, 0, id);
            soda.resolve(user);
            await ctx.state.users.setUser(user.getUsername(), user);
            await ctx.state.session.set('username', user.getUsername());
            ctx.response.redirect("/");
            return;
        } else {
            const entry = rows[0];
            let compare = await bcrypt.compare(u.password, entry["password"])
            if (!compare){
                throw new Error("Incorrect login credentials");
            }
            const verifyUser = await ctx.state.users.hasUser(entry["username"]);
            if (!verifyUser){
                throw new Error("Error retrieving the user!");
            }
            const user = await ctx.state.users.getUser(entry["username"]);
            await ctx.state.users.setUser(user.getUsername(), user);
            await ctx.state.session.set('username', user.getUsername());
            ctx.response.redirect("/");
            return;
        }
    } catch (err){
        
        await ctx.render("./views/error.ejs", {data:{error: err}});
    }

});


/* ==================== REPORT ==================== */
router.post('/report', async (ctx: Context) => {
    const raw = ctx.request.body({ type: "json" });
    const body = await raw.value;
    const url = body?.url || "" as string;
    
    const recaptcha = body['g-recaptcha-response'];
    if (!recaptcha) {
        ctx.response.status = Status.Forbidden;
        ctx.response.body = "missing captcha";
        return;
    }
    
    const res = await fetch('https://www.google.com/recaptcha/api/siteverify', {
        method: 'POST',
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },        
        body: `secret=${Deno.env.get('RECAPTCHA_KEY')}&response=${recaptcha}`
    });
    const j = await res.json();
    if (!j.success) {
        ctx.response.status = Status.Forbidden;
        ctx.response.body = "invalid captcha";
        return;
    }
    
    try {
        if (url) {
            await visit(url);
        } else {
            ctx.response.body = "Invalid URL provided";
        }
    } catch (e) {
        ctx.response.body = "An error occurred, sorry!";
    }

    ctx.response.body = "URL has been processed.";
});


/* ==================== LOGOUT ==================== */
router.get('/logout', async (ctx: Context) => {
    await ctx.state.session.deleteSession();
    ctx.response.redirect('/');
});

export default router;

