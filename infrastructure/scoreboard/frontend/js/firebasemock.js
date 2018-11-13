/**
 * @fileoverview Mock of firebase database for tests.
 */

goog.module('ctf.FirebaseMock');
goog.setTestOnly();

class FirebaseMock {
  constructor(db, keyPath, key, parent = null) {
    this.db = db;
    this.keyPath = keyPath;
    this.key = key;
    this.parent = parent;
    this.children = new Map;
    this.filter = _ => true;
    this.resolve = null;
    this.promise = null;
    this.refresh_();
  }
  refresh_() {
    let promise = new Promise(res => this.resolve = _ => res(this.refresh_()));
    this.promise = promise;
  }
  child(key) {
    if (!this.children.has(key)) {
      this.children.set(
          key,
          new FirebaseMock(this.db, this.keyPath.concat(this.key), key, this));
    }
    return this.children.get(key);
  }
  orderByChild(key) {
    return {
      equalTo: value => {
        this.filter = obj => obj[key] == value;
        return this;
      }
    };
  }
  getParentRef_() {
    return this.keyPath.reduce((db, key) => db[key] = db[key] || {}, this.db);
  }
  notify(value) {
    if (value && typeof value == 'object')
      Object.keys(value).forEach(k => this.child(k).notify(value[k]));
    this.resolve();
  }
  async set(value) {
    value = JSON.parse(JSON.stringify({value}, (k, v) => {
                  if (v == FirebaseMock.ServerValue.TIMESTAMP) {
                    v = new Date().getTime();
                  }
                  return v;
                })).value;
    let parentRef = this.getParentRef_();
    parentRef[this.key] = value;
    this.notify(value);
    if (this.parent) this.parent.set(parentRef);
  }
  push(value) {
    let key = (new Date().getTime() + Math.random())
                  .toString(36)
                  .replace(/\W+/g, '-');
    this.child(key).set(value);
    return {key, val: ()=>value};
  }
  async on(event, callback) {
    while (true) {
      await this.promise;
      this.once(event, callback);
    }
  }
  once(event, callback) {
    switch (event) {
      case 'value':
        return this.onceValue_();
      case 'child_removed':
        let original = callback;
        callback = v => {
          if (!v.val()) original(v);
        };
      default:
        return this.onceChild_(callback);
    }
  }
  get_() {
    let value = this.getParentRef_()[this.key];
    if (typeof value == 'undefined') {
      value = null;
    }
    return value;
  }
  onceValue_() {
    let value = this.get_();
    return {val: () => value, key: this.key};
  }
  onceChild_(callback) {
    let value = this.get_();
    if (typeof value == 'object') {
      Object.keys(value).forEach(key => {
        if (this.filter(value[key])) {
          callback({key: key, val: () => value[key]});
        }
      });
    }
  }
}

FirebaseMock.ServerValue = {
  TIMESTAMP: {}
};

exports = FirebaseMock;
