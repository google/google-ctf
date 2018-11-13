/**
 * @fileoverview Initializes the scoreboard.
 */

goog.module('ctf.Bootstrap');

const Scoreboard = goog.require('ctf.Scoreboard');

/** @define {string} API Key for CTF scoreboard */
goog.define('API_KEY', '');
/** @define {string} Auth Domain for CTF scoreboard */
goog.define('AUTH_DOMAIN', '');
/** @define {string} Database URL for CTF scoreboard */
goog.define('DATABASE_URL', '');
/** @define {string} Project ID for CTF scoreboard */
goog.define('PROJECT_ID', '');
/** @define {string} Storage Bucket for CTF scoreboard */
goog.define('STORAGE_BUCKET', '');

(function(firebase) {
  firebase.initializeApp({
    apiKey: document.currentScript.dataset.apiKey || API_KEY,
    authDomain: document.currentScript.dataset.authDomain || AUTH_DOMAIN,
    databaseURL: document.currentScript.dataset.databaseUrl || DATABASE_URL,
    projectId: document.currentScript.dataset.projectId || PROJECT_ID,
    storageBucket:
        document.currentScript.dataset.storageBucket || STORAGE_BUCKET,
  });
  new Scoreboard(firebase).init();
})(firebase);
