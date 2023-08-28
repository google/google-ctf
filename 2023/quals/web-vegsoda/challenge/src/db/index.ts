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
import { Client } from "https://deno.land/x/mysql/mod.ts";


// @ts-ignore  
import * as bcrypt from "https://deno.land/x/bcrypt/mod.ts";

// Open a database
const db = await new Client().connect({
  hostname: Deno.env.get("DB_HOST"),
  username: "forge",
  db: "forge",
  poolSize: 4,
  password: Deno.env.get("DB_PASSWORD"),
});


// Create all the tables
//await db.execute(`DROP TABLE IF EXISTS users;`);
await db.execute(`
  CREATE TABLE IF NOT EXISTS users (
    userid varchar(100) PRIMARY KEY,
    premium INT,
    username varchar(100) UNIQUE,
    password varchar(100),
    status varchar(100)
  );
`);
await db.execute(`
  CREATE TABLE IF NOT EXISTS posts (
    postid varchar(100) PRIMARY KEY,
    content TEXT,
    username varchar(100),
    FOREIGN KEY(username) REFERENCES users(username)
  );
`);
await db.execute(`
  CREATE TABLE IF NOT EXISTS sodas (
    sodaid varchar(100) PRIMARY KEY, 
    destinationuser varchar(100),
    sourceuser varchar(100),
    variety varchar(100),
    note TEXT,
    FOREIGN KEY(destinationuser) REFERENCES users(username),
    FOREIGN KEY(sourceuser) REFERENCES users(username)
  );
`);
await db.execute(`
  CREATE TABLE IF NOT EXISTS vios (
    vioid varchar(100) PRIMARY KEY, 
    username varchar(100),
    warning TEXT,
    FOREIGN KEY(username) REFERENCES users(username)
  );
`);
await db.execute(`
  CREATE TABLE IF NOT EXISTS logs (
    logid INT PRIMARY KEY AUTO_INCREMENT,
    date DATETIME DEFAULT CURRENT_TIMESTAMP,
    content TEXT
  );
`);


/*============== POPULATE WITH ADMIN ==============*/
const password = Deno.env.get("ADMIN_PASSWORD") || "DummyAdminPasswordThatsNotTheSameOnRemote";
const adminhash = await bcrypt.hash(password);

if (await return_admin() === false) {
    await db.execute(`INSERT INTO users (userid, premium, username, password, status) VALUES (?, 1, 'admin', ?, ?)`, [crypto.randomUUID(), adminhash, "I like Soda"]);
}
/* ============== FUNCTIONS ==============*/

async function return_admin() {
  const res = await db.query(`SELECT * FROM users WHERE username = ?`, ['admin']);
  if (res.length) {
      return res[0];
  }
  return false;
}

async function insert_stan_user<S extends string>(userid: S, username: S, password: S){
    await db.execute(`INSERT INTO users (userid, premium, username, password, status) VALUES (?, 0, ?, ?, ?)`, [userid, username, password, ""]);
}

async function insert_log<S extends string>(serialized: S, date: Date){
    await db.execute(`INSERT INTO logs (date, content) VALUES (?, ?)`, [date, serialized]);
}

async function insert_soda<S extends string>(sodaid: S, destinationuser: S, sourceuser: S, variety: S, note: S,){
    await db.execute('INSERT INTO sodas (sodaid, destinationuser, sourceuser, variety, note) VALUES (?, ?, ?, ?, ?)', [sodaid, destinationuser, sourceuser, variety, note]);
}

async function insert_vio<S extends string>(vioid: S, username: S, warning: S){
    await db.execute('INSERT INTO vios (vioid, username, warning) VALUES (?, ?, ?)', [vioid, username, warning]);
}

async function insert_post<S extends string>(postid: S, username: S, content: S){
    await db.execute('INSERT INTO posts (postid, username, content) VALUES (?, ?, ?)', [postid, username, content]);
}

async function select_from_db<S extends string, O extends object>(db_name: S, option: S, param: S): Promise<O[]>{
    const results = await db.query(`SELECT * FROM ?? WHERE ?? = ?`, [db_name, option, param]);
    return results;
}

async function update_db<S extends string, O extends object>(db_name: S, change: S, param: S, where: S, wherequery: S){
    await db.execute(`UPDATE ?? SET ?? = ? WHERE ?? = ?`, [db_name, change, param, where, wherequery]);
}

async function delete_from_db<S extends string>(db_name: S, change: S, param: S){
    await db.execute(`DELETE FROM ??} WHERE ?? = ?`, [db_name, change, param]);
}

export default {
    return_admin,
    select_from_db,
    update_db,
    delete_from_db,
    insert_post,
    insert_vio,
    insert_soda,
    insert_log,
    insert_stan_user
}
