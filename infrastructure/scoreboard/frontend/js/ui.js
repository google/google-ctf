/**
 * @fileoverview Defines the interactions between the Theme and the Scoreboard.
 */

goog.module('ctf.UI');

class UI {
  constructor(runtime) {
    this.runtime = runtime;
    this.cache_ = new Map();
    this.cacheAll_ = new Map();
    this.taskPoints = new Map();
    this.taskTeams = new Map();
    this.teamName = null;
  }
  async joinTeam(teamKey) {
    let teamName = await this.runtime.session.joinTeam(teamKey);
    if (teamName) {
      this.getNode_('sb-main').dataset.teamName = teamName;
      let loginLink = this.getNode_('sb-main').querySelector('.sb-login-link');
      if (loginLink) {
        loginLink.dataset.teamName = teamName;
      }
      this.taskTeams.forEach((teams, taskName) => {
        this.getNode_('sb-task', taskName).dataset.solved = teams.has(teamName);
      });
      this.teamName = teamName;
    } else {
      throw 'User tried to join an invalid team.';
    }
  }
  getNode_(type, id = null) {
    let selector = this.getSelector_(type, id);
    let node = this.cache_.get(selector);
    if (!node) {
      node = document.querySelector(selector);
      if (!node) {
        node = document.querySelector('.' + selector);
        if (!node) {
          node = this.createNode_(type, id);
        }
      }
      this.cache_.set(selector, node);
      node.activated = new Promise(function(res) {
        node.resolve = res;
      });
    }
    return node;
  }
  getSelector_(type, id = null) {
    return `${type}${id ? `[data-id="${id}"]` : ''}`;
  }
  createNode_(type, id) {
    let selector = this.getSelector_(type);
    let node = document.createElement(selector);
    node.dataset.id = id;
    node.dataset.sb = true;
    node.dataset.type = type;
    this.cacheAll_.set(selector, this.cacheAll_.get(selector) || []);
    this.cacheAll_.get(selector).push(node);
    return node;
  }
  updateTeam(team) {
    let teamNode = this.getNode_('sb-team', team.name);
    teamNode.dataset.taskSummary = [...team.tasks.values()].length + ' tasks';
    teamNode.dataset.tasks = [...team.tasks.keys()].join(',');
    teamNode.title = 'Solved tasks: ' + (teamNode.dataset.tasks || 'none');
    teamNode.dataset.last = team.last;
    teamNode.dataset.score = team.score;
    teamNode.dataset.rank = team.rank;
    let top100 = team.rank <= 100 || team.name == this.teamName;
    teamNode.dataset.top100 = top100;
    teamNode.dataset.top10 = team.rank <= 10 || team.name == this.teamName;
    teamNode.style.setProperty('--rank', team.rank);
    if (!teamNode.parentNode && top100) {
      this.getNode_('sb-teamList').appendChild(teamNode);
    }
  }
  updateScoreHistory(teamName, rank, history, limits) {
    let labelNode = this.getNode_('sb-chart-label', `rank-${rank}`);
    labelNode.dataset.name = teamName;
    let {topScore, lastTime} = this.prepareGraph_(limits);
    let points = history.map(point => {
      return [200 * point[0] / lastTime, 100 - 100 * point[1] / topScore];
    });
    let seriesNode = this.getNode_('g', `rank-${rank}`);
    let lineNode = seriesNode.querySelector('polyline');
    if (lineNode) {
      lineNode.setAttribute('points', points.join(' '));
    }
    let titleNode = seriesNode.querySelector('polyline title');
    if (titleNode) {
      titleNode.textContent = teamName;
    }
    let pointsNodes = seriesNode.querySelectorAll('circle,text');
    [...pointsNodes].forEach(node => node.parentNode.removeChild(node));
    points.forEach((point, i) => {
      let circleNode = seriesNode.appendChild(
          document.createElementNS('http://www.w3.org/2000/svg', 'circle'));
      let textNode = seriesNode.appendChild(
          document.createElementNS('http://www.w3.org/2000/svg', 'text'));
      circleNode.setAttribute('cx', point[0]);
      circleNode.setAttribute('cy', point[1]);
      circleNode.setAttribute('r', 1);
      circleNode
          .appendChild(
              document.createElementNS('http://www.w3.org/2000/svg', 'title'))
          .textContent = history[i][2];
      textNode.setAttribute('dx', -point[0] / 25);
      textNode.setAttribute('dy', -3);
      textNode.setAttribute('x', point[0]);
      textNode.setAttribute('y', point[1]);
      textNode.textContent = history[i][1];
    });
  }
  prepareGraph_(limits) {
    let topScore = 400 * Math.ceil(limits.topScore / 400);
    let lastTime = limits.lastTime;
    let graphNode = this.getNode_('g', 'labels');
    if (topScore != graphNode.dataset.topScore) {
      for (let i = 0; i < 5; i++) {
        let vLabel = this.getNode_('text', `v-label-${i}`);
        vLabel.textContent = Math.floor(i * 100 * (topScore / 400));
      }
    }
    return {topScore, lastTime};
  }
  getAllNodes_(type) {
    let selector = this.getSelector_(type);
    let result = this.cacheAll_.get(selector) ||
        [...document.querySelectorAll(selector)];
    this.cacheAll_.set(selector, result);
    return result;
  }
  setMetadataForBeginnersTaskKey(
      taskKey, {name, description, category, label, link, host, attachment}) {
    let taskNode = this.getNode_('sb-beginners-task', taskKey);
    taskNode.dataset.name = name || '';
    taskNode.dataset.description = description || '';
    taskNode.dataset.category = category || '';
    taskNode.dataset.label = label || '';
    taskNode.dataset.link = link || '';
    taskNode.dataset.host = host || '';
    taskNode.dataset.attachment = attachment || '';
    if (!taskNode.parentNode) {
      this.getNode_('sb-beginners-tasks').appendChild(taskNode);
    }
  }
  setBeginnersTaskSolved(taskKey, flag) {
    let taskNode = this.getNode_('sb-beginners-task', taskKey);
    let graphNode = this.getNode_('g', `beginners-${taskKey}`);
    graphNode.dataset.solved = taskNode.dataset.solved = true;
    let edges = [...graphNode.querySelectorAll('line')];
    edges.forEach(line => {
      let x = line.getAttribute('x2'), y = line.getAttribute('y2');
      let selector = `circle[cx="${x}"][cy="${y}"]`;
      let nodes = [...graphNode.parentElement.querySelectorAll(selector)];
      nodes.forEach(node => {
        node.parentNode.dataset.visible = true;
        node.parentNode.setAttribute('aria-disabled', false);
      });
    });
    this.getNode_('sb-main').dataset.beginnersDone = graphNode.dataset.last;
    let inputNode = taskNode.querySelector('input[type="text"]');
    if (inputNode) {
      inputNode.value = flag;
    }
  }
  setMetadataForTaskKey(
      taskKey, {name, description, category, label, link, host, attachment}) {
    let taskNode = this.getNode_('sb-task', taskKey);
    taskNode.style.display = category ? '' : 'none';
    taskNode.dataset.name = name || '';
    taskNode.dataset.description = description || '';
    taskNode.dataset.label = label || '';
    taskNode.dataset.link = link || '';
    taskNode.dataset.host = host || '';
    taskNode.dataset.attachment = attachment || '';
    this.setCategoryForTaskNode_(taskNode, category);
  }
  setCategoryForTaskNode_(taskNode, category) {
    let categoryNode = this.getNode_('sb-category', category);
    if (taskNode.parentNode != categoryNode) {
      categoryNode.appendChild(taskNode);
    }
    if (!categoryNode.parentNode) {
      this.getNode_('sb-categoryList').appendChild(categoryNode);
    }
  }
  setPointsForTask(taskName, task) {
    let node = this.getNode_('sb-task', taskName);
    this.taskPoints.set(task, task.getPoints());
    this.taskTeams.set(taskName, task.teams);
    node.dataset.points = task.getPoints();
    node.dataset.solves = task.getSolves();
    node.dataset.teams = [...task.teams.keys()].slice(0, 3).join(', ');
    node.dataset.solved = task.teams.has(this.teamName);
  }
  setActiveBeginnersTask(taskName) {
    let node = this.getNode_('sb-beginners-task', taskName);
    this.getAllNodes_('sb-beginners-task')
        .forEach(node => node.dataset.active = false);
    node.dataset.active = true;
    node.dataset.wrongFlag = false;
    node.dataset.error = '';
    return node;
  }
  setActiveTask(taskName) {
    let node = this.getNode_('sb-task', taskName);
    this.getAllNodes_('sb-task').forEach(node => node.dataset.active = false);
    node.dataset.active = true;
    return node;
  }
  showLocation(page, subpage) {
    let main = this.getNode_('sb-main');
    main.dataset.content = page;
    main.dataset.subpage = subpage || '';
  }
  async submitBeginnersFlag(task, flag) {
    await this.runtime.beginners.submitFlag(task, flag);
  }
  async submitFlag(task, flag) {
    await this.runtime.session.team.submitFlag(task, flag);
  }
  updateReadme(id, {title, order, content, silent, click}) {
    let node = this.getNode_('sb-update', id);
    node.dataset.title = title || '';
    node.dataset.content = content || '';
    if (click) {
      node.dataset.click = click;
    }
    node.style.setProperty('order', order);
    node.tabIndex = 10e3 + order;
    if (!node.parentNode) {
      this.getNode_('sb-readme').appendChild(node);
      if (!silent) {
        this.getNode_('sb-main').dataset.newReadme = true;
      }
    }
  }
}

exports = UI;
