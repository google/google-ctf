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

/* ==================== CHANGE USER STATUS ==================== */
router.all('/status', async (ctx: Context) => {
    try {
        console.log("hit");
        var username = await ctx.state.session.get('username');
        console.log(username);
        if (!username || !ctx.state.users.hasUser(username)){
            throw new Error("Error retrieving user.");
        }

        const user = await ctx.state.users.getUser(username) as User;
        var content = "";
        var type = "Status";
        
        if (user.getPrem() === 0){
            throw new Error("Sorry, only admins have statuses!");
        }

        if (ctx.request.url.searchParams.has("content")){
            content = ctx.request.url.searchParams.get("content");
            if (ctx.request.url.searchParams.has("type")){
                type = ctx.request.url.searchParams.get("type");
            }
            const qSubmission = ctx.state.queue.submitToQueue(username, content, type);
            if (!qSubmission){
                throw new Error("An error occurred during queue processing a new status.");
            }
            ctx.response.redirect("/profile");
            return;
        } else if (ctx.request.hasBody){
            const req = await ctx.request.body({ type: "json" }).value;
            content = req["content"];
            if (req["type"]){
                type = req["type"];
            }
            const qSubmission = ctx.state.queue.submitToQueue(username, content, type);
            if (!qSubmission){
                throw new Error("An error occurred during queue processing a new status.");
            }
            ctx.response.body = "Status succesfully changed";
            return;
        }
        const csrf = await ctx.state.session.get("csrf");
        var status = user.getStatus();

        if (!status){
            //default status
            status = "Man I just love. Vegetables.";
        }
        ctx.render("./views/status.ejs", {data:{username: user.getUsername(), status: status, csrf_token: csrf}});

    } catch (err) {
        await ctx.render("./views/error.ejs", {data:{error: err}});
    }
});

export default router;
