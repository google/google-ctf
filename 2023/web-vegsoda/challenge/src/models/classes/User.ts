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

import Post from "./Post.ts";
import Soda from "./Soda.ts";
import Warning from "./Warning.ts";

export default class User{
    public id: string;
    public username: string;
    public posts: Map<string, Post>;
    public warnings: Map<string, Warning>;
    public sodas: Map<string, Soda>;
    public status: string;
    public premium: Number = 0;
    
    public constructor(
        u: string, 
        prem: Number, 
        id?:string) {
        if (!id){
            this.id = crypto.randomUUID();
        } else {
            this.id = id;
        }
        this.username = u;
        this.posts = new Map<string, Post>();
        this.warnings = new Map<string, Warning>();
        this.sodas = new Map<string, Soda>();
        this.premium = prem;
    }

    public setStatus(c: string){
        if (this.getPrem() === 1) {
            this.status = c;
        }
    }

    public getStatus(){
        return this.status;
    }

    public pushToPost<P extends Post>(p: P){
        this.posts.set(p.id, p);
    }

    public pushToWarnings<W extends Warning>(w: W){
        this.warnings.set(w.vioid, w);
    }

    public pushToSodas<S extends Soda>(s: S){
        this.sodas.set(s.id, s);
    }

    public getUsername(): string {
        return this.username;
    }

    public getId(): string {
        return this.id;
    }

    public getPrem(): Number {
        return this.premium;
    }
}