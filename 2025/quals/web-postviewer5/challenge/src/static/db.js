/**
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

class DB {
  constructor() {
    const dbrequest = indexedDB.open("Files", 1);
    const that = this;
    dbrequest.onupgradeneeded = function () {
      let db = dbrequest.result;
      if (!db.objectStoreNames.contains("files")) {
        db.createObjectStore("files", { keyPath: "id" });
        db.createObjectStore("info", { keyPath: "id" });

        fetch('/static/comments.png').then(e => e.blob()).then(async blob => {
          const fileInfo = await that.addFile({
            id: 'comments',
            file: new File([blob], "New year, new Postviewer!!", { type: 'image/png' }),
            cached: true,
            isPublic: false
          });

          window?.appendFileInfo(fileInfo);
        });
      }
    };

    this.dbPromise = new Promise((resolve) => {
      dbrequest.onsuccess = function () {
        resolve(dbrequest.result);
      };
    });
  }

  async addFile({ id, file, cached, isPublic}) {
    const db = await this.dbPromise;
    const transaction = db.transaction(["files", "info"], "readwrite");
    const filesdb = transaction.objectStore("files");
    const infodb = transaction.objectStore("info");

    const req = filesdb.put({ id, file, cached, isPublic });
    return new Promise((resolve) => {
      req.onsuccess = () => {
        const fileInfo = { id, name: file.name, cached, isPublic, date: Date.now() };
        const req = infodb.put(fileInfo);
        req.onsuccess = () => {
          resolve(fileInfo);
        };
        req.onerror = () => {
          throw new Error("Error while adding a file");
        };
      };
      req.onerror = () => {
        throw new Error("Error while adding a file");
      };
    });
  }

  async getFiles() {
    const db = await this.dbPromise;
    const filesdb = db.transaction("info", "readonly").objectStore("info");
    const req = filesdb.getAll();
    return new Promise((resolve) => {
      req.onsuccess = () => {
        resolve(req.result);
      };
    });
  }

  async getFile(id) {
    const db = await this.dbPromise;
    const filesdb = db.transaction("files", "readonly").objectStore("files");
    const req = filesdb.get(id);
    return new Promise((resolve) => {
      req.onsuccess = () => {
        resolve(req.result);
      };
    });
  }

  async clear() {
    const db = await this.dbPromise;
    const transaction = db.transaction(["files", "info"], "readwrite");
    return new Promise(async (resolve) => {
      const req1 = transaction.objectStore("files").clear(),
        req2 = transaction.objectStore("info").clear();
      await Promise.all([
        new Promise((r) => (req1.onsuccess = r)),
        new Promise((r) => (req2.onsuccess = r)),
      ]);
      resolve(true);
    });
  }
}
