/**
 * @fileoverview Defines the database interactions and schema.
 */

goog.module('ctf.Database');

const DatabaseSchema = {
  USER_TEAMS: 'userTeams',
  TEAMS: 'teams',
  TEAMS_TASKS: 'tasks',
  TEAM_NAME: 'name',
  MAPPING: 'mapping',
  TASKS: 'tasks',
  TASKS_SOLVED: 'solved',
  TASK_SOLUTIONS: 'taskSolutions',
  SCOREBOARD: 'scoreboard',
  SCOREBOARD_TASKS: 'tasks',
  RECRUITING: 'recruiting',
  TEAM_LOG: 'teamLog',
  README: 'readme',
  BEGINNERS: 'beginners',
  BEGINNERS_TASKS: 'tasks',
  BEGINNERS_FLAGS: 'flags'
};

class Database {
  constructor(firebaseDatabaseRef, ServerValue) {
    this.databaseRef = firebaseDatabaseRef;
    this.ServerValue = ServerValue;
  }
  async changeTeamNameForTeamKey(teamKey, teamName) {
    // If this is a name change, we first need to delete the old mapping.
    let currentName = await this.getTeamNameFromTeamKey(teamKey);
    if (currentName && currentName != teamName) {
      let currentMapping = this.getMappingRefFromTeamName_(currentName);
      try {
        // Try to delete the current mapping. This will succeed if it was ours,
        // as long as we haven't submitted any tasks. If this fails, then that
        // means we either already have tasks, or it doesn't belong to us.
        await currentMapping.remove();
      } catch (e) {
      }
    }
    // Change the team name. This will succeed if the old mapping is gone, or if
    // it doesn't belong to us. This can fail if the old mapping belonged to us
    // but didn't get deleted in the previous step because we had already some
    // tasks solved under that name.
    await this.getTeamRefFromTeamKey_(teamKey)
        .child(DatabaseSchema.TEAM_NAME)
        .set(teamName);
    // Set the new mapping. This will succeed if the name matches the one we set
    // in the step above.
    await this.getMappingRefFromTeamName_(teamName).set(teamKey);
  }
  getMappingRefFromTeamName_(teamName) {
    return this.databaseRef.child(DatabaseSchema.MAPPING).child(teamName);
  }
  getTeamRefFromTeamKey_(teamKey) {
    return this.databaseRef.child(DatabaseSchema.TEAMS).child(teamKey);
  }
  async getTeamNameFromTeamKey(teamKey) {
    return (await this.getTeamRefFromTeamKey_(teamKey)
                .child(DatabaseSchema.TEAM_NAME)
                .once('value'))
        .val();
  }
  async submitBeginnersFlag(taskName, flag) {
    let result = await this.databaseRef.child(DatabaseSchema.BEGINNERS)
                     .child(DatabaseSchema.BEGINNERS_FLAGS)
                     .orderByValue()
                     .equalTo(flag)
                     .once('value');
    if (result.val()[taskName] != flag) {
      throw 'Error submitting beginners flag';
    }
  }
  async submitFlagForTeamKey(teamKey, task, flag) {
    let teamName = await this.getTeamNameFromTeamKey(teamKey);
    let solved = await this.recordFlagInTeam_(teamKey, task, flag);
    if (solved) {
      // If these fail, they'll be fixed in a Firebase function.
      try {
        await this.recordTaskSolution_(task, teamName, solved);
        await this.addSolvedTaskToScoreboard_(task, teamName, solved);
      } catch(e) {
        Promise.reject('Error committing flag.');
      }
    } else {
      throw 'Error submitting flag';
    }
  }
  async recordFlagInTeam_(teamKey, task, flag) {
    let submitRef = this.getTeamRefFromTeamKey_(teamKey)
                        .child(DatabaseSchema.TEAMS_TASKS)
                        .child(task);
    try {
      await submitRef.set({flag: flag, solved: this.ServerValue.TIMESTAMP});
    } catch (e) {
    }
    return (await submitRef.child(DatabaseSchema.TASKS_SOLVED).once('value'))
        .val();
  }
  async recordTaskSolution_(task, teamName, solved) {
    await this.databaseRef.child(DatabaseSchema.TASK_SOLUTIONS)
        .child(task)
        .child(teamName)
        .set(solved);
  }
  async addSolvedTaskToScoreboard_(task, teamName, solved) {
    await this.databaseRef.child(DatabaseSchema.SCOREBOARD)
        .child(teamName)
        .child(DatabaseSchema.SCOREBOARD_TASKS)
        .child(task)
        .set(solved);
  }
  async getTeamKeyFromUserId(userId) {
    let key = (await this.getTeamRefFromUserId_(userId).once('value')).val();
    if (!key) {
      key = this.databaseRef.child(DatabaseSchema.TEAMS).push().key;
    }
    return key;
  }
  getTeamRefFromUserId_(userId) {
    return this.databaseRef.child(DatabaseSchema.USER_TEAMS).child(userId);
  }
  async setTeamKeyForUserId(userId, teamKey) {
    await this.getTeamRefFromUserId_(userId).set(teamKey);
  }
  recordJoinedTeam(userId, teamKey, userEmail) {
    this.databaseRef.child(DatabaseSchema.TEAM_LOG)
        .child(teamKey)
        .child(userId)
        .set(userEmail);
  }
  recordEmailPreferences(userId, email) {
    this.databaseRef.child(DatabaseSchema.RECRUITING).child(userId).set(email);
  }
  onBeginnersTaskChanged(updateTask) {
    this.databaseRef.child(DatabaseSchema.BEGINNERS)
        .child(DatabaseSchema.BEGINNERS_TASKS)
        .on('child_added', snap => {
          updateTask(snap.key, snap.val());
        });
    this.databaseRef.child(DatabaseSchema.BEGINNERS)
        .child(DatabaseSchema.BEGINNERS_TASKS)
        .on('child_changed', snap => {
          updateTask(snap.key, snap.val());
        });
    this.databaseRef.child(DatabaseSchema.BEGINNERS)
        .child(DatabaseSchema.BEGINNERS_TASKS)
        .on('child_removed', snap => {
          updateTask(snap.key, {});
        });
  }
  onTaskChanged(updateTask) {
    this.databaseRef.child(DatabaseSchema.TASKS)
        .orderByChild('visible')
        .equalTo(true)
        .on('child_added', snap => {
          updateTask(snap.key, snap.val());
        });
    this.databaseRef.child(DatabaseSchema.TASKS)
        .orderByChild('visible')
        .equalTo(true)
        .on('child_changed', snap => {
          updateTask(snap.key, snap.val());
        });
    this.databaseRef.child(DatabaseSchema.TASKS)
        .orderByChild('visible')
        .equalTo(true)
        .on('child_removed', snap => {
          updateTask(snap.key, {});
        });
  }
  onTaskSolutionChanged(task, addTaskSolution) {
    this.databaseRef.child(DatabaseSchema.TASK_SOLUTIONS)
        .child(task)
        .on('child_added', snap => {
          addTaskSolution(snap.key, snap.val());
        });
    this.databaseRef.child(DatabaseSchema.TASK_SOLUTIONS)
        .child(task)
        .on('child_changed', snap => {
          addTaskSolution(snap.key, snap.val());
        });
    this.databaseRef.child(DatabaseSchema.TASK_SOLUTIONS)
        .child(task)
        .on('child_removed', snap => {
          addTaskSolution(snap.key, null);
        });
  }
  onTeamChanged(updateTeam) {
    this.databaseRef.child(DatabaseSchema.SCOREBOARD)
        .on('child_added', snap => {
          updateTeam(snap.key, snap.val());
        });
    this.databaseRef.child(DatabaseSchema.SCOREBOARD)
        .on('child_changed', snap => {
          updateTeam(snap.key, snap.val());
        });
    this.databaseRef.child(DatabaseSchema.SCOREBOARD)
        .on('child_removed', snap => {
          updateTeam(snap.key, {});
        });
  }
  onReadmeChanged(updateReadme) {
    this.databaseRef.child(DatabaseSchema.README).on('child_added', snap => {
      updateReadme(snap.key, snap.val());
    });
    this.databaseRef.child(DatabaseSchema.README).on('child_changed', snap => {
      updateReadme(snap.key, snap.val());
    });
    this.databaseRef.child(DatabaseSchema.README).on('child_removed', snap => {
      updateReadme(snap.key, {});
    });
  }
}

exports = Database;
