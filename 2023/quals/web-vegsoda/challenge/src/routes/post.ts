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
import { Router, Context, helpers } from 'https://deno.land/x/oak/mod.ts';
import Post from '../models/classes/Post.ts';
import User from '../models/classes/User.ts';
import Vio from '../models/classes/Vio.ts';
import serializer from "../utils/serializer.ts";
import { AppState } from '../utils/session.ts';

const router = new Router<AppState>();

router.get('/post/:postId', async (ctx: Context) => {
    try {
        const username = await ctx.state.session.get('username');
        const userState = await ctx.state.users;

        const verifyUser = await userState.hasUser(username);
    
        if (!username || !verifyUser) {
            const user_err = new Error("Error retrieving user.");
            throw user_err;
        }
    
        const user = await userState.getUser(username) as User;
        const { postId } = await helpers.getQuery(ctx, { mergeParams: true });
    
        if (user.posts.has(postId)){
            var post = user.posts.get(postId);
            if (user.getPrem() === 0){
                ctx.render("./views/standardpost.ejs", {data:{id: post.id, content: post.giveContent()}});
                return;
            } else if (user.getPrem() === 1){
                ctx.render("./views/premiumpost.ejs", {data:{id: post.id, content: post.giveContent()}});
                return;
            }
            return;
        } else {
            throw Error("Couldn't find specified post.");
        }
    } catch (err) {
        ctx.render("./views/error.ejs", {data:{error: err}});
    }

});

router.post('/newpost', async (ctx: Context) => {
    try {
        const username = await ctx.state.session.get('username');
        const verifyUser = await ctx.state.users.hasUser(username);
        if (!username || !verifyUser) {
            const user_err = new Error("Error retrieving user.");
            throw user_err;
        }
        const user = await ctx.state.users.getUser(username) as User;
        if (user.warnings.size >= 10){
            const warnings_err = new Error("You have committed too many violations! Some of your privileges have been revoked.");
            throw warnings_err;
        }
        const post = await ctx.request.body({ type: "json" }).value;
        //XSS check
        const regex  = '(\b)(on\S+)(\s*)=|javascript|<(|\/|[^\/>][^>]+|\/[^>][^>]+)>';
        const xss = post.content.match(regex);
        if (xss && user.getPrem() === 0){
            const vioid = crypto.randomUUID();
            const vio = Vio.getVio("XSS", user.getUsername(), vioid);
            const serializedvio = serializer.serialize(vio);
            const qSubmission = ctx.state.queue.submitToQueue(user.getUsername(), serializedvio, "Vio");
            if (!qSubmission){
                const queue_err = new Error("An error occurred during queue processing vio.");
                throw queue_err;
            }
        }
    
        const newpost = new Post(post.content, user.getId());
        const serializednewpost = serializer.serialize(newpost);
    
        const qSubmission = await ctx.state.queue.submitToQueue(user.getUsername(), serializednewpost, "Post");
        if (!qSubmission){
            const queue_err = new Error("An error occurred during queue processing.");
            throw queue_err;
        }
        if (!xss) {
            ctx.response.body = 'Post succesfully made! Please wait - your post will be processed shortly.'
        } else {
            ctx.response.body = 'Be careful - XSS characters were detected in your post. It will be processed shortly, but a violation has been assigned to you.'
        }
        
    } catch (err){
        await ctx.render("./views/error.ejs", {data:{error: err}});
    }
});

export default router;
