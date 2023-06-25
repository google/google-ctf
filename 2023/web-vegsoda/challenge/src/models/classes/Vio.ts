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

import Message from '../interfaces/Message.ts';
import User from './User.ts';
import Warning from './Warning.ts';

// @ts-ignore  
import { toDeserialize, toSerialize, } from "https://deno.land/x/superserial/mod.ts";

enum Level {
    xss_detected = "XSS", 
    unauth_access = "UNAUTHORIZED ACCESS",
    unknown = "UNKNOWN"
}

export default class Vio implements Message {
    public id: string;
    public userid: string;
    public level: Level;
    private warning: Warning;

    static getVio<S extends string>(s: S, userid: string, id?:string): Vio {
        switch(s){
            case "XSS":
                var v = new Vio(Level.xss_detected, userid, id);
                break;
            case "UNAUTHORIZED ACCESS":
                var v = new Vio(Level.unauth_access, userid, id);
                break;
            default:
                var v = new Vio(Level.unknown, userid, id);
                break;
        }
        return v;
    }
    
    constructor(lvl: Level, userid: string, id?: string){
        if (id){
            this.id = id;
        } else {
            this.id = crypto.randomUUID();
        }
        this.userid = userid;
        this.level = lvl;
    }

    resolveWarning(user: User) {
        this.warning = new Warning(this.id, this.level);
        this.warning.assign(user);
    }

    validate(user: User): boolean{
        if (!this.warning) {
            return false;
        }
        if (user.getId() === this.userid){
            this.warning.assign(user);
            return true;
        } else {
            return this.warning.resolve(user);
        }
    }


    dispatch(): string{
        return `VIOLATION DETECTED:
                --- ID:  ${this.id}
                --- LEVEL: ${this.level}
                --- USER: ${this.userid}`;
    }

    [toSerialize]() {
        return {
          id: this.id,
          userid: this.userid,
          level: this.level,
          warning: this.warning,
        };
    }

    [toDeserialize](
        value: {
          id: string;
          level: Level;
          warning: Warning;
          userid: string;
        }
      ) {
        this.id = value.id;
        this.userid = value.userid;
        this.level = value.level;
        this.warning = value.warning;
        this.warning.vioid = value.id;
        this.warning.offense = value.level;
    }
}
