/**
 * @fileoverview CTF Scoreboard Main Class.
 */

goog.module('ctf.Scoreboard');

const Beginners = goog.require('ctf.Beginners');
const Database = goog.require('ctf.Database');
const Readme = goog.require('ctf.Readme');
const Session = goog.require('ctf.Session');
const TaskList = goog.require('ctf.TaskList');
const TeamList = goog.require('ctf.TeamList');
const Theme = goog.require('ctf.Theme');
const UI = goog.require('ctf.UI');

class Scoreboard {
  constructor(firebase) {
    this.firebase = firebase;
    this.session = null;
    this.beginners = null;
  }
  init() {
    let database = new Database(
        this.firebase.database().ref(), this.firebase.database.ServerValue);
    let ui = new UI(this);
    let taskList = new TaskList(database, ui);
    let teamList = new TeamList(database, ui, taskList, window);
    let readme = new Readme(database, ui);
    let beginners = new Beginners(database, ui);
    teamList.loadTeams();
    taskList.loadTasks();
    readme.loadReadme();
    beginners.loadTasks();
    this.beginners = beginners;
    this.session = new Session(this.firebase.auth, database);
    let materialUpgrader = () => {};
    if (window.componentHandler) {
      materialUpgrader =
          window.componentHandler.upgradeElement.bind(window.componentHandler);
    }
    (new Theme(window.document.body, ui, window, materialUpgrader)).init();
  }
}

exports = Scoreboard;
