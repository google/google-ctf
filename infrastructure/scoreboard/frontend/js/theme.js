/**
 * @fileoverview Themes define how to transform the elements created by the
 *     scoreboard into functional HTML and how to trigger different actions.
 */

goog.module('ctf.Theme');

class Theme {
  constructor(rootNode, ui, window, opt_newElementCallback) {
    this.rootNode = rootNode;
    this.ui = ui;
    this.window = window;
    this.newElementCallback_ = opt_newElementCallback || (() => {});
    this.flags = null;
    this.cache = new WeakMap();
    this.teamKeyParam = 'TeamSecretKey';
    this.lastKeyboardPresses = [];
  }
  init() {
    this.autoLogin();
    this.window.addEventListener('hashchange', _ => {
      this.updateLocation();
    });
    this.window.addEventListener('popstate', _ => {
      this.updateLocation();
    });
    this.updateLocation();
    this.rootNode.addEventListener('click', e => this.handleEvent(e));
    this.rootNode.addEventListener('mouseover', e => this.handleEvent(e));
    this.rootNode.addEventListener('submit', e => this.handleEvent(e));
    this.rootNode.addEventListener('keydown', e => this.handleEvent(e));
    this.rootNode.addEventListener('keypress', e => this.handleEvent(e));
    this.rootNode.addEventListener('focus', e => this.handleEvent(e));
    let attribute = new MutationObserver(list => this.attributeChange(list));
    attribute.observe(this.rootNode, {subtree: true, attributes: true});
    let child = new MutationObserver(list => this.childChange(list));
    child.observe(this.rootNode, {subtree: true, childList: true});
    this.window.setInterval(() => this.sortInterval(), 1e3);
  }
  sortInterval() {
    let sorted =
        this.rootNode.querySelectorAll('[data-sort-by][data-unsorted="true"]');
    [...sorted].forEach(node => {
      let property = node.dataset.sortBy;
      [...node.children]
          .sort((a, b) => a.dataset[property] - b.dataset[property])
          .forEach(child => child.dataset[property] && node.appendChild(child));
      node.dataset.unsorted = false;
    });
  }
  updateLocation() {
    let page = this.window.location.hash.slice(1) || 'home';
    let [content, id] = page.split('/');
    this.ui.showLocation(content, id);
    switch (content) {
      case 'challenges':
        this.setActiveTask(id);
        break;
      case 'beginners':
        this.setActiveBeginnersTask(id);
        this.populateBeginnersFlags();
    }
  }
  async setActiveTask(id) {
    let task = this.ui.setActiveTask(id || '$');
    if (id) await task.activated;
    let inactiveDialogs = this.rootNode.querySelectorAll(
        'sb-task:not([data-active="true"]) dialog');
    let dialog = task.querySelector('dialog');
    if (dialog) dialog.showModal();
    [...inactiveDialogs].forEach(dialog => dialog.close());
  }
  async setActiveBeginnersTask(id) {
    let task = this.ui.setActiveBeginnersTask(id || '$');
    if (id) await task.activated;
    let inactiveDialogs = this.rootNode.querySelectorAll(
        'sb-beginners-task:not([data-active="true"]) dialog');
    let dialog = task.querySelector('dialog');
    if (dialog) dialog.showModal();
    [...inactiveDialogs].forEach(dialog => dialog.close());
  }
  autoLogin() {
    let teamKey = null;
    let params = new URLSearchParams(this.window.location.search);
    if (params.has(this.teamKeyParam)) {
      teamKey = params.get(this.teamKeyParam);
    } else {
      teamKey = this.window.localStorage.getItem(this.teamKeyParam);
    }
    if (teamKey) {
      try {
        this.joinTeam(teamKey);
      } catch (e) {
      }
    }
  }
  populateBeginnersFlags() {
    let flagsJson = this.window.localStorage.getItem('beginnersFlags') || '{}';
    if (flagsJson) {
      this.flags = JSON.parse(flagsJson);
      for (var task in this.flags) {
        this.ui.setBeginnersTaskSolved(task, this.flags[task]);
      }
    }
  }
  handleEvent(event) {
    let type = event.type;
    if (type == 'keypress' && (event.keyCode == 32 || event.keyCode == 13)) {
      type = 'click';
    }
    if (type == 'focus') {
      type = 'mouseover';
    }
    for (let node = event.target; node.parentNode; node = node.parentNode) {
      if (node.dataset[type]) {
        let actions = node.dataset[type];
        actions.split(',').forEach(
            action => this.handleAction(action, node, event));
        break;
      }
    }
  }
  async handleAction(action, node, event) {
    let main = this.rootNode.querySelector('sb-main');
    let input = (node.querySelector('input[type="text"]') || {}).value;
    let id = node.dataset.id;
    let wasError = false, trackAction = true;
    action = action.split('/').map(part => unescape(part));
    switch (action[0]) {
      case 'keyDown':
        trackAction = false;
        if (main.dataset.subpage && (event.keyCode == 27)) {
          this.window.location.hash = main.dataset.content + '/';
        }
        this.lastKeyboardPresses.push(event.keyCode);
        this.lastKeyboardPresses = this.lastKeyboardPresses.slice(-10);
        // compare the last 10 keyboard inputs with the konami code:
        // [38, 38, 40, 40, 37, 39, 37, 39, 66, 65]
        if (this.lastKeyboardPresses.join() ==
            atob('JiYoKCUnJSdCQQ')
                .split('')
                .map(function(c) {
                  return c.charCodeAt(0);
                })
                .join()) {
          this.window.location.href = '//youtu.be///KEkrWRHCDQU';
        }
        break;
      case 'showLocation':
        this.ui.showLocation(action[1]);
        this.window.location.hash = action[1];
        break;
      case 'toggleMenu':
        main.dataset.menu = main.dataset.menu ? '' : true;
        break;
      case 'setBeginnersTaskActive':
        let forTask = node.dataset.for;
        if (forTask && node.dataset.visible != 'true') {
          return;
        }
        if (forTask && action[1] == 'true') {
          this.window.location.hash = `beginners/${forTask}`;
        } else {
          this.window.location.hash = 'beginners/';
        }
        break;
      case 'submitBeginnersFlag':
        try {
          node.dataset.wrongFlag = false;
          node.dataset.error = '';
          await this.ui.submitBeginnersFlag(id, input);
          this.rememberBeginnersFlag_(id, input);
          this.window.location.hash = 'beginners/';
        } catch (e) {
          node.dataset.wrongFlag = true;
          node.dataset.error = e;
          wasError = e;
        }
        break;
      case 'setTaskActive':
        while (node.dataset.type != 'sb-task' && node.parentNode) {
          node = node.parentNode;
        }
        if (node.dataset.id && action[1] == 'true') {
          this.window.location.hash = `challenges/${node.dataset.id}`;
        } else {
          this.window.location.hash = 'challenges/';
        }
        node.dataset.wrongFlag = false;
        node.dataset.error = '';
        break;
      case 'submitFlag':
        try {
          node.dataset.wrongFlag = false;
          node.dataset.error = '';
          await this.ui.submitFlag(id, input);
          this.window.location.hash = 'challenges/';
        } catch (e) {
          if (!this.ui.runtime.session.team) {
            this.window.location.hash = 'login';
          } else {
            node.dataset.wrongFlag = true;
            node.dataset.error = e;
          }
          wasError = e;
        }
        break;
      case 'joinTeam':
        node.dataset.accountError = false;
        if (input) {
          try {
            await this.joinTeam(input);
            this.window.location.hash = 'challenges';
          } catch (e) {
            node.dataset.accountError = true;
            Promise.reject(e);
            wasError = e;
          }
        }
        break;
      case 'login':
        this.login();
        break;
      case 'logout':
        if (this.ui.runtime.session.team) this.logout();
        break;
      case 'createTeam':
        let teamName = action[1] || input;
        node.dataset.accountError = false;
        if (teamName) {
          try {
            await this.createTeam(teamName);
            this.window.location.hash = 'login';
          } catch (e) {
            node.dataset.accountError = true;
            Promise.reject(e);
            wasError = e;
            node.dataset.error = e;
          }
        }
        break;
      case 'recoverTeam':
        await this.recoverTeam();
        break;
      case 'logEmail':
        let allowed = node.querySelector('input[type="checkbox"]').checked;
        this.logEmail(allowed);
        break;
      case 'openLink':
        node.setAttribute('href', node.textContent);
        node.protocol = 'https';
        node.target = '_blank';
        break;
      case 'loadMore':
        main.dataset.showAll = main.dataset.showAll ? '' : true;
        break;
      case 'clearReadme':
        main.dataset.newReadme = false;
        break;
      case 'togglePotato':
        main.dataset.potato = main.dataset.potato != 'true';
    }
    if (trackAction) {
      this.window._gaq.push([
        '_trackEvent', action[0],
        action.concat([id, wasError ? 'error' : '']).join('/'),
        [wasError, input].join('/')
      ]);
    }
  }
  async joinTeam(teamKey) {
    await this.ui.joinTeam(teamKey);
    this.showTeamKey(teamKey);
  }
  showTeamKey(teamKey) {
    this.window.history.replaceState(
        {}, '', `?${this.teamKeyParam}=${teamKey}${this.window.location.hash}`);
    this.window.localStorage.setItem(this.teamKeyParam, teamKey);
    let node =
        this.rootNode.querySelector('sb-login-dialog input[type="text"]');
    if (node) {
      node.value = teamKey;
    }
  }
  async logEmail(allowed) {
    await this.login();
    this.ui.runtime.session.logEmail(allowed);
  }
  async login() {
    if (!this.ui.runtime.session.user) await this.ui.runtime.session.login();
  }
  logout() {
    this.window.localStorage.removeItem(this.teamKeyParam);
    this.window.location = '?';
  }
  async createTeam(teamName) {
    await this.login();
    let teamKey = await this.ui.runtime.session.createTeam(teamName);
    await this.joinTeam(teamKey);
  }
  async recoverTeam() {
    await this.login();
    let team = await this.ui.runtime.session.recoverTeam();
    await this.joinTeam(team.teamKey);
  }
  rememberBeginnersFlag_(task, flag) {
    this.flags[task] = flag;
    this.window.localStorage.setItem(
        'beginnersFlags', JSON.stringify(this.flags));
  }
  attributeChange(list) {
    let nodes = list.filter(
                        mut => mut.attributeName.match(/^data-/) &&
                            mut.target.dataset.sb == 'true')
                    .map(mut => mut.target);
    this.updateNodes(nodes);
  }
  childChange(list) {
    let nodes = [].concat.apply(
        [],
        list.map(
            m => [...m.addedNodes].filter(
                n => n.dataset && n.dataset.sb == 'true')));
    let children = nodes.map(n => [...n.querySelectorAll('[data-sb="true"]')]);
    this.updateNodes([].concat.apply(nodes, children));
  }
  updateNodes(nodes) {
    [...new Set(nodes)].forEach(node => this.updateNode(node));
  }
  updateNode(node) {
    if (!this.cache.has(node)) {
      let template = this.rootNode.querySelector(`template#${node.nodeName}`);
      if (!template) return;
      let clone = template.content.cloneNode(true);
      let parentNode = node;
      if (template.dataset.tagName) {
        parentNode = document.createElement(template.dataset.tagName);
        node.parentElement.insertBefore(parentNode, node);
        parentNode.appendChild(node);
      }
      let varNodes = [...clone.querySelectorAll('sb-var')];
      this.cache.set(node, varNodes);
      for (var v in template.dataset) {
        parentNode.dataset[v] = template.dataset[v];
      }
      if (template.className) {
        parentNode.className += ' ' + template.className;
      }
      parentNode.insertBefore(clone, parentNode.firstChild);
      node.sbParentNode = parentNode;
      node.sbParentNode.dataset.unsorted = true;
      this.newElementCallback_(node);
      if (node.resolve) node.resolve();
    }
    let sortBy = node.sbParentNode.parentNode.dataset.sortBy;
    if (node.dataset[sortBy] != node.dataset['old' + sortBy]) {
      node.dataset['old' + sortBy] = node.dataset[sortBy];
      node.sbParentNode.parentNode.dataset.unsorted = true;
    }
    if (node.sbParentNode != node) {
      for (var v in node.dataset) {
        node.sbParentNode.dataset[v] = node.dataset[v];
      }
      [...node.children].forEach(child => {
        node.sbParentNode.appendChild(child);
      });
    }
    this.cache.get(node).forEach(
        varNode => varNode.textContent = node.dataset[varNode.dataset.var]);
  }
}

exports = Theme;
