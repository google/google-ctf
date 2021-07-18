/**
 * Copyright 2021 Google LLC
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

const mariadb = require('mariadb')
const crypto = require('crypto');

module.exports = {
  initialised: false
}

function genId(){
  return crypto.randomInt(2**48-1);
}

const DB_HOST = process.env.DB_HOST || "127.0.0.1";
const DB_DATABASE = process.env.DB_DATABASE || "secdriven";
const DB_USER = process.env.DB_USER || "secdriven";
const DB_PASSWORD = process.env.DB_PASSWORD || 'Eesh6asoo8ei';
const DB_PORT = process.env.DB_PORT || "13306";
const DB_CONNECTION_LIMIT = parseInt(process.env.DB_CONNECTION_LIMIT) || 100;

const FLAG_PATH = process.env.FLAG_PATH || '/home/ctfuser/flag';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin';
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_FILE_ID = process.env.ADMIN_FILE_ID || 133711377731;
const ADMIN_ID = process.env.ADMIN_ID || 731379997131;

const pool = mariadb.createPool({
  database: DB_DATABASE,
  host: DB_HOST,
  user: DB_USER,
  password: DB_PASSWORD,
  port: DB_PORT,
  connectionLimit: DB_CONNECTION_LIMIT
});

(async function () {
  let conn;
  try {
    conn = await pool.getConnection();

    await conn.query(`
CREATE TABLE IF NOT EXISTS users (
  id BIGINT UNSIGNED NOT NULL,
  name CHAR(15) NOT NULL UNIQUE KEY,
  password CHAR(30) NOT NULL,
  PRIMARY KEY (id)
);
`);

// INDEX(owner) is used to speed up calling getFiles function
    await conn.query(`
CREATE TABLE IF NOT EXISTS files (
  id BIGINT UNSIGNED NOT NULL,
  name CHAR(100) NOT NULL,
  path CHAR(50) NOT NULL,
  owner BIGINT UNSIGNED NOT NULL,
  public BOOLEAN DEFAULT 0,
  size INT,
  PRIMARY KEY (id),
  INDEX(owner)
);
`);

// The first foreign key is used to ensure only valid file IDs are inserted
// but also speeds up requesting user's files from getFiles function
// The second foreign key will prevent inserting non-existent user IDs
  await conn.query(`
CREATE TABLE IF NOT EXISTS shares (
  file_id BIGINT UNSIGNED NOT NULL,
  to_id BIGINT UNSIGNED NOT NULL,
  CONSTRAINT \`fk_shares_file\` FOREIGN KEY (file_id) REFERENCES files (id),
  CONSTRAINT \`fk_shares_users\` FOREIGN KEY (to_id) REFERENCES users (id),
  PRIMARY KEY (file_id, to_id)
);
`);

  await conn.query(`
  REPLACE INTO users(id, name, password) VALUES(?,?,?);
  `, [ADMIN_ID, ADMIN_USERNAME, ADMIN_PASSWORD])

  await conn.query(`
  REPLACE INTO files(id, name, path, owner, public) VALUES(?, ?, ?, ?, ?)
  `, [ADMIN_FILE_ID,'flag.html',FLAG_PATH,ADMIN_ID,0])

  } catch (err) {
    console.error(err);
  } finally {
    module.exports.initialised = true;
    if (conn) return conn.end();
  }
})()

async function register(user, password) {
  let conn;
  let result = "Error";

  try {
    conn = await pool.getConnection();
    result = await conn.query("INSERT IGNORE INTO users(id, name, password) VALUES(?, ?, ?)", [genId(), user, password]);
  } catch (err) {
    console.error(err);
  } finally {
    if (conn) conn.end();
    return result;
  }
}

async function login(user, password){
  let conn;
  let result = "Error";

  try {
    conn = await pool.getConnection();
    result = await conn.query("SELECT id, name FROM users WHERE name = ? AND password = ? LIMIT 1", [user, password]);
  } catch (err) {
    console.error(err);
  } finally {
    if (conn) conn.end();
    return result;
  }
}

async function existsUser(user, id){
  let conn;
  let result = "Error";

  try {
    conn = await pool.getConnection();
    result = await conn.query("SELECT 1 FROM users WHERE id = ? AND name = ? LIMIT 1", [id, user]);
  } catch (err) {
    console.error(err);
  } finally {
    if (conn) conn.end();
    return result;
  }
}

async function getFiles(id){
  let conn;
  let result = "Error";

  try {
    conn = await pool.getConnection();
    result = await conn.query("SELECT id,owner,name,size,public FROM files f LEFT JOIN shares s ON f.id = s.file_id WHERE s.to_id = ? UNION SELECT id,owner,name,size,public FROM files WHERE owner = ?", [id, id]);
  } catch (err) {
    console.error(err);
  } finally {
    if (conn) conn.end();
    return result;
  }
}

async function addFile(owner, name, path, size, public=false){
  let conn;
  let result = "Error";

  if(owner == ADMIN_ID) return result;

  try {
    conn = await pool.getConnection();
    const file_id = genId();
    const rs = await conn.query("INSERT INTO files(id, name, path, owner, size, public) VALUES(?, ?, ?, ?, ?, ?)", [file_id, name, path, owner, size, public]);
    if(rs.affectedRows == 1) result=file_id
  } catch (err) {
    console.error(err);
  } finally {
    if (conn) conn.end();
    return result;
  }
}

async function getFile(id){
  let conn;
  let result = "Error";

  try {
    conn = await pool.getConnection();
    result = await conn.query("SELECT * FROM files WHERE id = ? LIMIT 1", [id]);
  } catch (err) {
    console.error(err);
  } finally {
    if (conn) conn.end();
    return result;
  }
}

async function shareFile(file_id, to_ids, from){
  let conn;
  let result = "Error";

  if(from == ADMIN_ID) return result;
  let nested_values = [];

  if(typeof to_ids === "number"){
    nested_values = [[file_id, to_ids]];
  } else {
    nested_values = to_ids.filter(n => n != ADMIN_ID).map(n => [file_id, n]);
  }

  try {
    conn = await pool.getConnection();
    result = await conn.batch("INSERT IGNORE INTO shares(file_id, to_id) VALUES (?, ?)", nested_values);
  } catch (err) {
    console.error(err);
  } finally {
    if (conn) conn.end();
    return result;
  }
}

async function isSharedFile(file_id, user){
  let conn;
  let result = "Error";

  try {
    conn = await pool.getConnection();
    result = await conn.query("SELECT 1 FROM shares WHERE file_id = ? AND to_id = ? LIMIT 1", [file_id, user]);
  } catch (err) {
    console.error(err);
  } finally {
    if (conn) conn.end();
    return result;
  }
}

Object.assign(module.exports,{
  register,
  login,
  existsUser,
  getFiles,
  addFile,
  getFile,
  shareFile,
  isSharedFile
});

