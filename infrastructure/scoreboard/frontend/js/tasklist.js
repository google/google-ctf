/**
 * @fileoverview Synchronizes the list of tasks across the database and the ui.
 */

goog.module('ctf.TaskList');

/** @define {boolean} whether to use linear scoring **/
goog.define('USE_LINEAR_SCORING', true);

class TaskList {
  constructor(database, ui) {
    this.database = database;
    this.ui = ui;
    this.tasks = new Map();
    this.tasksPromises = new Set();
  }
  loadTasks() {
    this.database.onTaskChanged((key, val) => {
      this.taskChanged_(key, val);
    });
  }
  taskChanged_(key, val) {
    let task = this.tasks.get(key);
    if (!this.tasks.has(key)) {
      this.tasks.set(key, task = new Task(key));
      this.ui.setPointsForTask(key, task);
      this.database.onTaskSolutionChanged(key, (teamName, timestamp) => {
        task.addSolve(teamName, timestamp);
        this.ui.setPointsForTask(key, task);
      });
    }
    task.setCategory(val.category);
    this.ui.setMetadataForTaskKey(key, val);
  }
}

class Task {
  constructor(key) {
    this.key = key;
    this.teams = new Map;
    this.category = null;
  }
  setCategory(category) {
    this.category = category;
  }
  addSolve(team, timestamp) {
    if (timestamp) {
      this.teams.set(team, timestamp);
    } else {
      this.teams.delete(team);
    }
  }
  getPoints(timestamp) {
    let minScore = 50, maxScore = 500;
    if (USE_LINEAR_SCORING) {
      return Math.max(
          minScore, maxScore - Math.max(0, this.getSolves(timestamp) - 1) * 50);
    } else {
      let V = 3, K = 80;
      return Math.max(
          minScore,
          Math.floor(
              maxScore -
              K *
                  Math.log2(
                      (Math.max(1, this.getSolves(timestamp)) + V) / (1 + V))));
    }
  }
  getSolves(timestamp = Infinity) {
    return [...this.teams.values()]
        .filter(solved => solved <= timestamp)
        .length;
  }
}

exports = TaskList;
