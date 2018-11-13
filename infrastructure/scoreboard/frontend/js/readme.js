/**
 * @fileoverview Loads FAQs, updates, and announcements.
 */

goog.module('ctf.Readme');

class Readme {
  constructor(database, ui) {
    this.database = database;
    this.ui = ui;
  }
  loadReadme() {
    this.database.onReadmeChanged((key, val) => {
      this.ui.updateReadme(key, val);
    });
  }
}

exports = Readme;
