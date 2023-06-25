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
import Log from "./Log.ts";
import Soda from "./Soda.ts";
import Vio from "./Vio.ts";
import User from "./User.ts";
import UserManager from './UserManager.ts';

import serializer from "../../utils/serializer.ts";

enum QueueState {
    Ready = 1,
    Processing
  }

export default class BatchQueue {
    private static instance: BatchQueue;
    public items: QueueItem[];
    private state: QueueState;

    private constructor() { 
        this.items = new Array();
        this.state = QueueState.Ready;
    }

    public static getInstance(): BatchQueue {
        if (!BatchQueue.instance) {
            BatchQueue.instance = new BatchQueue();
        }
        return BatchQueue.instance;
    }

    public static deleteInstance(): void {
        if (!BatchQueue.instance) {
            return;
        }
        BatchQueue.instance = null;
    }

    public checkLength(): boolean {
        return this.items.length >= 3;
    }

    public submitToQueue(user: string, item: string, name: string): boolean {
        try {
            if (this.state === QueueState.Processing){
                throw Error();
            }
            const submission = new QueueItem(user, item, name);
            this.items.push(submission);
            return true;
        } catch (e){
            return false;
        }
    }

    public async processQueue(users: UserManager): Promise<Log[]>{
        this.state = QueueState.Processing;
        const logs = new Array<Log>();
        for (let i = 0; i < this.items.length; i++){
            const qItem = this.items[i] as QueueItem;
            const userExists = await users.hasUser(qItem.user);
            if (!userExists) {
                continue
            }
            const user = await users.getUser(qItem.user) as User;
            switch(qItem.processName){
                case "Soda":
                    var soda = null;
                    try {
                        soda = serializer.deserialize(qItem.toProcess) as Soda;
                        soda.apply();
                        soda.resolve(user);
                    } catch {
                        break;
                    }
                    const sodalog = new Log(soda);
                    sodalog.apply(user);
                    logs.push(sodalog);
                    break;
                case "Post":
                    var post = null;
                    try {
                        post = serializer.deserialize(qItem.toProcess) as Post;
                        Post.resolve(post, user, post.content);
                    } catch {
                        break;
                    }
                    const postlog = new Log(post);
                    postlog.apply(user);
                    logs.push(postlog);
                    break;
                case "Vio":
                    var vio = null;
                    try {
                        vio = serializer.deserialize(qItem.toProcess) as Vio;
                        vio.resolveWarning(user);
                    } catch {
                        break;
                    }
                    const violog = new Log(vio);
                    violog.apply(user);
                    logs.push(violog);
                    break;
                case "Status":
                    user.setStatus(qItem.toProcess);
                    break;
                default:
                    break;
            }
            await users.setUser(user.getUsername(), user);
        }
        this.items = [];
        this.state = QueueState.Ready;
        return logs;
    }

}

class QueueItem {
    public user: string;
    public toProcess: any;
    public processName: string;

    constructor(user: string, itemToProcess: any, processName: string){
        this.user = user;
        this.toProcess = itemToProcess;
        this.processName = processName;
    }
}

