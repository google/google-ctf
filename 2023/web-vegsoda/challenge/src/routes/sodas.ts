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
import { Router, helpers, Context} from 'https://deno.land/x/oak/mod.ts';
import User from '../models/classes/User.ts';
import Soda from '../models/classes/Soda.ts';
import Vio from '../models/classes/Vio.ts';
import serializer from '../utils/serializer.ts';
import { AppState } from '../utils/session.ts';

const router = new Router<AppState>();

router.get('/sodas/:sodaId', async (ctx: Context) => {
    try {
        const { sodaId } = helpers.getQuery(ctx, { mergeParams: true });
        const username = await ctx.state.session.get('username');
        const verifyUser = await ctx.state.users.hasUser(username);
        if (!username || !verifyUser){
            const user_err = new Error("Error retrieving user.");
            throw user_err;
        }
        const user = await ctx.state.users.getUser(username) as User;

        if (user.sodas.has(sodaId)){
            const soda = user.sodas.get(sodaId) as Soda;
            if (user.getPrem() === 0){
                ctx.render("./views/standardsoda.ejs", {data:{id: soda.id, variety: soda.variety.toString(), note: soda.note, sender: soda.src}});
                return;
            } else if (user.getPrem() === 1){
                ctx.render("./views/premiumsoda.ejs", {data:{id: soda.id, variety: soda.variety.toString(), note: soda.note, sender: soda.src}});
                return;
            }
            
        }
        return;
    } catch (err) {
        await ctx.render("./views/error.ejs", {data:{error: err}});
    }

});


router.post('/newsoda', async (ctx: Context) => {
    try {
        const req = ctx.request.body({ type: "json" });
        const u = await req.value;
    
        const username = await ctx.state.session.get('username');
        const sourceUser = await ctx.state.users.getUser(username) as User;
        const destinationUser = await ctx.state.users.getUser(u["dest"]) as User;

        if (!sourceUser || !destinationUser|| !username){
            const user_err = new Error("Error retrieving user.");
            throw user_err;
        }

        if (sourceUser.warnings.size >= 10){
            const warnings_err = new Error("You have committed too many violations! Some of your privileges have been revoked.");
            throw warnings_err;
        }
    
        if (sourceUser.getPrem() !== 1 && destinationUser.getPrem() === 1){
            const vioid = crypto.randomUUID();
            const vio = Vio.getVio("UNAUTHORIZED ACCESS", sourceUser.getUsername(), vioid);
            const serializedvio = serializer.serialize(vio);
            const qSubmission = ctx.state.queue.submitToQueue(sourceUser.getUsername(), serializedvio, "Vio");
            if (!qSubmission){
                const queue_err = new Error("An error occurred during queue processing vio.");
                throw queue_err;
                
            }
            const access_err = new Error("You cannot send a soda to a premium user as a standard user. A warning will be added to your profile.");
            throw access_err;
        }

        var note = "";

        if (!u.note) {
            note = "Veggie Soda lovers unite!";
        }

       
        const dest = destinationUser.getUsername();
        const src = sourceUser.getUsername();
        const variety = u.variety;

        const soda = Soda.getSoda(variety, src, note);
        const serializedsoda = serializer.serialize(soda);
        const qSubmission = ctx.state.queue.submitToQueue(dest, serializedsoda, "Soda");
        if (!qSubmission){
            const queue_err = new Error("An error occurred in queue processing.");
            throw queue_err;
        }
        ctx.response.body = "Soda succesfully sent! Please wait, it will take some time to process your soda.";
        return;
    } catch (err) {
        await ctx.render("./views/error.ejs", {data:{error: err}});
    }


});
export default router;
