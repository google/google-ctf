/**
 * @fileoverview Keeps track of the user's session state and mutations.
 */

goog.module('ctf.Session');

class Session {
  constructor(firebaseAuth, database) {
    this.firebaseAuth = firebaseAuth;
    this.database = database;
    this.user = null;
    this.team = null;
  }
  async login() {
    let provider = new this.firebaseAuth.GoogleAuthProvider();
    let loginResult = await this.firebaseAuth().signInWithPopup(provider);
    this.user = loginResult.user;
    this.tryToRecordTeam();
  }
  async getCreatorTeam() {
    let teamKey = await this.database.getTeamKeyFromUserId(this.user.uid);
    return new UserTeam(this.database, teamKey);
  }
  async setCreatorTeam(userTeam) {
    await this.database.setTeamKeyForUserId(this.user.uid, userTeam.teamKey);
  }
  async joinTeam(teamKey) {
    let userTeam = new UserTeam(this.database, teamKey);
    let teamName = await userTeam.getName();
    this.team = userTeam;
    this.tryToRecordTeam();
    return teamName;
  }
  tryToRecordTeam() {
    if (this.user && this.team) {
      this.database.recordJoinedTeam(
          this.user.uid, this.team.teamKey, this.user.email);
    }
  }
  async recoverTeam() {
    let userTeam = await this.getCreatorTeam();
    this.team = userTeam;
    await this.setCreatorTeam(userTeam);
    return userTeam;
  }
  async createTeam(teamName) {
    let userTeam = await this.recoverTeam();
    await userTeam.changeTeamName(teamName);
    return userTeam.teamKey;
  }
  async logEmail(allowed) {
    let email = allowed ? this.user.email : '';
    this.database.recordEmailPreferences(this.user.uid, email);
  }
}

class UserTeam {
  constructor(database, teamKey = null) {
    this.database = database;
    this.teamKey = teamKey;
  }
  async getName() {
    return await this.database.getTeamNameFromTeamKey(this.teamKey);
  }
  async changeTeamName(teamName) {
    await this.database.changeTeamNameForTeamKey(this.teamKey, teamName);
  }
  async submitFlag(task, flag) {
    await this.database.submitFlagForTeamKey(this.teamKey, task, flag);
  }
}

exports = Session;
