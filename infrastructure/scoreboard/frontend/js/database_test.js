/**
 * @fileoverview Tests for Scoreboard Database functions.
 */

goog.module('ctf.DatabaseTest');
goog.setTestOnly();

const Database = goog.require('ctf.Database');
const FirebaseMock = goog.require('ctf.FirebaseMock');

describe('client expectations from database security rules', () => {
  let firebaseDbMock, database;
  beforeEach(function() {
    firebaseDbMock = new FirebaseMock({}, [], 'root');
    database = new Database(firebaseDbMock, FirebaseMock.ServerValue);
  });

  it('changes team name for team key', async () => {
    let key = 'aBcDeF', name = 'SomeName';
    await database.changeTeamNameForTeamKey(key, name);
    // Setting a team's name requires changing the mapping (name to key) and
    // the name under the team's property.
    expect(firebaseDbMock.db.root.mapping[name]).toBe(key);
    expect(firebaseDbMock.db.root.teams[key].name).toBe(name);
  });

  it('gets team name from team key', async () => {
    let key = 'aBcDeF', name = 'Team123';
    await firebaseDbMock.child('teams').child(key).child('name').set(name);
    expect(await database.getTeamNameFromTeamKey(key)).toBe(name);
    expect(await database.getTeamNameFromTeamKey('fail')).toBe(null);
  });

  it('submit flags for team key', async () => {
    let key = 'AxZ', task = 'a-bc', flag = 'C{F}', name = 'team1';
    firebaseDbMock.child('teams').child(key).child('name').set(name);
    let start = new Date().getTime() - 1;
    await database.submitFlagForTeamKey(key, task, flag);
    let solved = firebaseDbMock.db.root.scoreboard[name].tasks[task];
    expect(solved).toBeLessThan(new Date().getTime() + 1);
    expect(solved).not.toBeLessThan(start);
    expect(firebaseDbMock.db.root.taskSolutions[task][name]).toBe(solved);
    expect(firebaseDbMock.db.root.teams[key].tasks[task].solved).toBe(solved);
    expect(firebaseDbMock.db.root.teams[key].tasks[task].flag).toBe(flag);
  });

  it('gets team key from user id', async () => {
    let uid = 'WsQ', key = 'sAw';
    firebaseDbMock.child('userTeams').child(uid).set(key);
    expect(await database.getTeamKeyFromUserId(uid)).toBe(key);
  });

  it('sets team key for user id', async () => {
    let uid = 'BnX', key = 'qAs';
    await database.setTeamKeyForUserId(uid, key);
    expect(firebaseDbMock.db.root.userTeams[uid]).toBe(key);
  });

  it('records email preferences', async () => {
    let uid = 'XyZaBc', email = 'user@gmail.com';
    await database.recordEmailPreferences(uid, email);
    expect(firebaseDbMock.db.root.recruiting[uid]).toBe(email);
  });

  it('records joined team', async () => {
    let uid = 'XyZaBc', team = 'aBcDeF', email = 'user@gmail.com';
    await database.recordJoinedTeam(uid, team, email);
    expect(firebaseDbMock.db.root.teamLog[team][uid]).toBe(email);
  });

  it('tracks visible tasks',
     () => new Promise(res => {
       let task = 'web-foo';
       database.onTaskChanged((key, val) => {
         expect(key).toBe(task);
         res();
       });
       firebaseDbMock.child('tasks').child(task + 1).set({});
       firebaseDbMock.child('tasks').child(task + 2).set({visible: false});
       firebaseDbMock.child('tasks').child(task).set({visible: true});
       firebaseDbMock.child('tasks').child(task + 3).set({});
     }));

  it('tracks task solutions',
     () => new Promise(res => {
       let task = 'web-bar', team = 'bteam', solved = 43;
       database.onTaskSolutionChanged(task, (key, val) => {
         expect(key).toBe(team);
         expect(val).toBe(solved);
         res();
       });
       firebaseDbMock.child('taskSolutions').child(task).child(team).set(43);
     }));

  it('tracks team changes',
     () => new Promise(res => {
       let teamName = 'ateam';
       database.onTeamChanged((teamKey, val) => {
         expect(teamKey).toBe(teamName);
         res();
       });
       firebaseDbMock.child('scoreboard').child(teamName).set({});
     }));

  it('submits a flag on a new team',
     () => new Promise(async res => {
       let uid = 'uXeAsN', teamName = 'Free Orca', task = 'web-100';
       database.onTeamChanged((team, val) => {
         expect(team).toBe(teamName);
         expect(Object.keys(val.tasks)).toContain(task);
         res();
       });
       let teamKey = await database.getTeamKeyFromUserId(uid);
       await database.setTeamKeyForUserId(uid, teamKey);
       await database.changeTeamNameForTeamKey(teamKey, teamName);
       let submitFlag = true;
       database.onTaskChanged((task, val) => {
         if (submitFlag) {
           database.submitFlagForTeamKey(teamKey, task, 'CTF{}');
           submitFlag = false;
         }
       });
       firebaseDbMock.child('tasks').child(task).set({visible: true});
     }));
});
