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
import { toDeserialize, toSerialize, } from "https://deno.land/x/superserial/mod.ts";
import User from "./User.ts";

export default class Log{
    date: Date;
    public e: any;
    public constructor(e: any) {
        this.e = e;
        this.date = new Date();
    }

    public generate(){
        switch(this.e.constructor.name){
            case "ApplicationErrorEvent":
                console.log(`%c============= ERROR [${this.date}]`, "color:red");
                console.log(this.e.message);
                break;
            default:
                console.log(`%c============= MISC. LOG [${this.date}]`, "color:blue");
                if (typeof this.e === "undefined"){
                    console.log("OBJECT IS UNDEFINED.");
                } else {
                    if (this.e.dispatch){
                        console.log(this.e.dispatch());
                    } 
                }
                break;
        }
    }

    public apply(u: User){
        if (!this.e.validate){
            return;
        }
        if (this.e.validate(u)){
            this.generate();
        }
    }

    public getDate(){
        return this.date;
    }
    
    [toSerialize]() {
        return {
          date: this.date,
          e: this.e,
        };
    }

    [toDeserialize](
        value: {
          date: Date;
          e: any;
        }){
            this.date = value.date;
            this.e = value.e;
    }

}
