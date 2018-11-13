/**
 * @fileoverview Synchronizes the list of teams across the database and the UI.
 */

goog.module('ctf.TeamList');

class TeamList {
  constructor(database, ui, taskList, window) {
    this.database = database;
    this.ui = ui;
    this.taskList = taskList;
    this.window = window;
    this.teams = new Map;
    this.firstTime = Infinity;
    this.lastTime = 0;
    this.topScore = 0;
    this.timeout = 0;
  }
  loadTeams() {
    this.database.onTeamChanged((key, val) => {
      this.teamChanged_(key, val);
    });
    this.database.onTaskChanged(() => {
      this.sortScoreboardOnce_();
    });
  }
  teamChanged_(name, val) {
    let team = this.teams.get(name) || new Team(name);
    this.teams.set(name, team);
    let tasks = val.tasks;
    for (let taskName in tasks) {
      let time = tasks[taskName];
      this.firstTime = Math.min(this.firstTime, time);
      this.lastTime = Math.max(this.lastTime, time);
      team.addTask(taskName, time);
    }
    this.sortScoreboardOnce_();
  }
  sortScoreboardOnce_() {
    if (!this.timeout) {
      this.timeout = this.window.setTimeout(() => {
        this.timeout = 0;
        this.sortScoreboard_();
      }, 1e3);
    }
  }
  sortScoreboard_() {
    this.teams.forEach(team => {
      let taskNames = [...team.tasks.keys()];
      team.setScore(taskNames.reduce((score, taskName) => {
        let task = this.taskList.tasks.get(taskName);
        return score + (task ? task.getPoints() : 0);
      }, 0));
      this.ui.updateTeam(team);
    });
    [...this.teams.values()]
        .sort((a, b) => (b.score - a.score) || (a.last - b.last))
        .map((team, rank) => {
          team.setRank(rank + 1);
          this.ui.updateTeam(team);
          return team;
        }).forEach((team, rank) => {
          if (rank < 10) {
            this.updateScoreHistory_(team);
          }
        });
  }
  updateScoreHistory_(team) {
    let tasks = [...team.tasks.entries()].sort((a, b) => a[1] - b[1]);
    let solvedTasks = [];
    let history = [[0, 0]];
    for (let [taskName, time] of tasks) {
      let task = this.taskList.tasks.get(taskName);
      if (task) {
        let score = 0;
        solvedTasks.push(task);
        for (let oldTask of solvedTasks) {
          score += oldTask.getPoints(time);
        }
        history.push([time - this.firstTime, score, taskName]);
        this.topScore = Math.max(score, this.topScore);
      }
    }
    history.push([this.lastTime - this.firstTime, team.score, '']);
    this.ui.updateScoreHistory(team.name, team.rank, history, {
      topScore: this.topScore,
      lastTime: this.lastTime - this.firstTime
    });
  }
}

class Team {
  constructor(name) {
    this.name = name;
    this.tasks = new Map;
    this.last = 0;
    this.score = 0;
    this.rank = null;
  }
  addTask(task, last) {
    this.tasks.set(task, last);
    this.last = Math.max(last, this.last);
  }
  setScore(score) {
    this.score = score;
  }
  setRank(rank) {
    this.rank = rank;
  }
}

exports = TeamList;
