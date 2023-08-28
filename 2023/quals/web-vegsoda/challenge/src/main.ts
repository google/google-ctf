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
import { Application, Context, send } from 'https://deno.land/x/oak/mod.ts';
// @ts-ignore  
import { oakAdapter } from "https://deno.land/x/view_engine@v10.5.1/mod.ts";
// @ts-ignore  
import { viewEngine, ejsEngine } from "https://deno.land/x/view_engine@v10.5.1/mod.ts";
// @ts-ignore  
import { Session, CookieStore } from "https://deno.land/x/oak_sessions/mod.ts";

import routes from './routes/index.ts';
import db from './db/index.ts';

import Log from './models/classes/Log.ts';
import BatchQueue from './models/classes/Queue.ts';
import UserManager from './models/classes/UserManager.ts';

import serializer from './utils/serializer.ts';
import { AppState } from './utils/session.ts';
import csrfMiddleware from './utils/csrf.ts';

const app = new Application<AppState>(
  {
    keys: [Deno.env.get("COOKIE_KEY")],
    proxy: true,
    secure: true,
    logErrors: false
  });

app.use(viewEngine(oakAdapter, ejsEngine));

const queue = BatchQueue.getInstance();
const store = new CookieStore(Deno.env.get("COOKIE_ENCRYPTION"), {cookieSetDeleteOptions: {
     sameSite: "none",
     secure: true
  }});
const port = parseInt(Deno.env.get("port")) || 1337 ;
const users = new UserManager();

/* ======= ADDING STATE ======= */
app.use(async (ctx: Context, next) => {
  ctx.state = {
    db,
    queue,
    users
  };
  await next();
});


/* ======= SESSION ======= */
app.use(Session.initMiddleware(store, {
  cookieSetOptions: {
     sameSite: "none",
     secure: true
  },
  cookieGetOptions: {}
}));

/* ======= STATIC FILES ======= */
app.use(async (ctx,next) => {
  try {
    const p = ctx.request.url.pathname;
    await send(ctx, p + (p.endsWith('/')?'index.html':''),{
      root: `${Deno.cwd()}/static`
       })
  } catch {
    await next();
  }
});

const csrf_key = Deno.env.get("CSRF_KEY") || "01234567890123456789012345678901";
const csrf = new csrfMiddleware(csrf_key, store);
app.use(csrf.csrf_protections());

app.use(routes.base.allowedMethods());
app.use(routes.base.routes());
app.use(routes.soda.allowedMethods());
app.use(routes.soda.routes());
app.use(routes.user.allowedMethods());
app.use(routes.user.routes());
app.use(routes.post.allowedMethods());
app.use(routes.post.routes());

app.use(routes.status.allowedMethods());
app.use(routes.status.routes());

/* ======= QUEUE CHECKING ======= */
const processFullQ = () => {
  const QueueFull = new CustomEvent("queuefull");
  app.dispatchEvent(QueueFull);
}

const checkTime = () => {
  if (queue.checkLength()) {
    processFullQ();
  }
};



/* ======= ERROR CATCHING ======= */
 app.addEventListener("error", async (err) => {
   const log = new Log(err);
   log.generate();
   await db.insert_log(serializer.serialize(log), log.getDate());
   err.preventDefault();
 });

/* ======= BATCH PROCESS ITEMS ======= */
app.addEventListener("queuefull", async () => {
  console.log("%c[BATCH_QUEUE] queue is full, processing now...", "color:orange");
  const logs = await queue.processQueue(users) as Array<Log>;
  for (let i = 0; i < logs.length; i++){
    //Insert logs into db
    await db.insert_log(serializer.serialize(logs[i]), logs[i].getDate());
  }
});

/* ======= START ======= */
app.addEventListener('listen', () => {
  //Runs every 45 s
  setInterval(checkTime, 1000 * 30);
  console.log(`%cListening on localhost:${port}`, "color:pink");
});



await app.listen( { port });
