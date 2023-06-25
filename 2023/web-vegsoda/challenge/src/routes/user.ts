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
import { Router, Context } from 'https://deno.land/x/oak/mod.ts';

import User from '../models/classes/User.ts';
import { AppState } from '../utils/session.ts';

const router = new Router<AppState>();


router.get('/profile', async (ctx: Context) => {
    var username = await ctx.state.session.get('username');
    const verifyUser = await ctx.state.users.hasUser(username);

    if (!username || !verifyUser){
        ctx.response.redirect('/');
        return;
    }
    const csrf = await ctx.state.session.get("csrf");
    const u = await ctx.state.users.getUser(username) as User;

    let posts = [...u.posts.entries()].reduce((obj, [key, value]) => (obj[key] = value["content"], obj), {});
    let sodas = [...u.sodas.entries()].reduce((obj, [key, value]) => (obj[key] = value["note"], obj), {});
    ctx.render("./views/profile.ejs", {data: {username: u.getUsername(), csrf_token: csrf},
        sodas: sodas, posts: posts});
});

export default router;
