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

import User from "./User.ts";
import Soda from "./Soda.ts";
import Post from "./Post.ts";
import Warning from "./Warning.ts";

import db from "../../db/index.ts";

export default class DBManager {

    public async getUser(username: string): Promise<User>{
        try {
            const u = await db.select_from_db("users", "username", username);
            if (u.length !== 0) {
                const user = new User(username, u[0]['premium'], u[0]['userid']);
                const sodas = await db.select_from_db("sodas", "destinationuser", user.getUsername());
                const posts = await db.select_from_db("posts", "username", user.getUsername());
                const vios = await db.select_from_db("vios", "username", user.getUsername());

                for (let i = 0; i < sodas.length; i++){
                    var soda = Soda.getSoda(sodas[i]["variety"], sodas[i]["sourceuser"], sodas[i]["note"], sodas[i]["sodaid"], sodas[i]["destinationuser"]);
                    user.pushToSodas(soda);
                }

                for (let i = 0; i < posts.length; i++){
                    var post = new Post(posts[i]["content"], user.getId(), posts[i]["postid"]);
                    user.pushToPost(post);
                }

                for (let i = 0; i < vios.length; i++){
                    var warning = new Warning(vios[i]['vioid'], vios[i]['warning']);
                    user.pushToWarnings(warning);
                }

                if (user.getPrem() === 1){
                    var status = u[0]["status"];
                    user.setStatus(status);
                }
                
                return user as User;
            }
            return null;
        } catch {
            return null;
        }
    }

    public async setUser<U extends User>(username: string, user: U, hash?: string): Promise<boolean>{
        try {
            //insert user into users table
            const test = await db.select_from_db("users", "username", username);
            if (test.length === 0 && hash) {
                await db.insert_stan_user(user.getId(), username, hash);
            }

            user.sodas.forEach(async (value: Soda, key: string) => {
                const sodas = await db.select_from_db("sodas", "sodaid", value.id);
                if (sodas.length === 0) {
                    try {
                        await db.insert_soda(value.id, value.dest, value.src, value.variety.toString(), value.note);
                    } catch (err) {
                        console.log(err);
                    }
                }
            });

            user.posts.forEach(async (value: Post, key: string) => {
                const posts = await db.select_from_db("posts", "postid", value.id);
                if (posts.length === 0) {
                    try {
                        await db.insert_post(value.id, user.getUsername(), value.giveContent());
                    } catch (err) {
                        console.log(err);
                    }
                }
            });

            user.warnings.forEach(async (value: Warning, key: string) => {
                const vios = await db.select_from_db("vios", "vioid", value.vioid);
                if (vios.length === 0) {
                    try {
                        await db.insert_vio(value.vioid, user.getUsername(), value.offense);
                    } catch (err) {
                        console.log(err);
                    }
                }
            });

            if (user.getPrem() === 1){
                try {
                    await db.update_db("users", "status", user.getStatus(), "username", user.getUsername());
                } catch(err) {
                    console.log(err);
                }
            }
            
        } catch {
            return false;
        }
        return true;
    }

    public async hasUser(username: string): Promise<boolean>{
        try {
            const user = await db.select_from_db("users", "username", username);
            if (user.length !== 0) {
                return true;
            }
            return false;
        } catch {
            return false;
        }
    }
}