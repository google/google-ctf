/*
Copyright 2019 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

let turnDeadline = null;
let maxTurnTime = null;
let ws = null;
let guessing = false;
let done = false;

function displayTime() {
  if (turnDeadline !== null) {
    const secondsLeft = (turnDeadline - Date.now())/1000;
    document.getElementById('time').textContent =
        secondsLeft.toFixed(1) + '/' + maxTurnTime;
    if (secondsLeft < 0) {
      alert('Time is up!');
      clearInterval(timeInterval);
      done = true;
    }
  }
}

const timeInterval = setInterval(displayTime, 100);

let resetCellsTimeout = null;
let cellsToReset = [];

function resetCells() {
  for (const pair of cellsToReset) {
    const x = pair[0];
    const y = pair[1];
    const cell = document.querySelectorAll('#board tr')[y].children[x];
    cell.textContent = '?';
    cell.className = 'unknown';
  }
  clearTimeout(resetCellsTimeout);
  resetCellsTimeout = null;
  cellsToReset = [];
}

function onWsOpen() {
  const msg = {
    op: 'info'
  };
  ws.send(JSON.stringify(msg));
}

function guess(x, y) {
  if (done) {
    alert('The game is over');
    return;
  }
  if (guessing) {
    alert("You're clicking too fast");
    return;
  }

  if (resetCellsTimeout !== null) {
    // If there's a resetCellsTimeout still waiting to happen, run it now
    // so that it doesn't erase the wrong things later.
    resetCells();
  }

  guessing = true;
  const msg = {
    op: 'guess',
    body: {
      x: x,
      y: y
    }
  };
  ws.send(JSON.stringify(msg));
}

function removeChildren(node) {
  while (node.firstChild) {
    node.removeChild(node.firstChild);
  }
}

function onResp(event) {
  const msg = JSON.parse(event.data);

  turnDeadline = Date.now() + msg.maxTurnTime*1000;
  maxTurnTime = msg.maxTurnTime;
  displayTime();
  document.getElementById('turns').textContent =
      msg.turnsUsed + '/' + msg.maxTurns;

  const table = document.getElementById('board');
  removeChildren(table);
  const height = msg.board.length/msg.width;
  for (let y = 0; y < height; ++y) {
    const row = table.insertRow();
    for (let x = 0; x < msg.width; ++x) {
      const cell = row.insertCell();
      const val = msg.board[y*msg.width + x];
      if (val < 0) {
        cell.textContent = '?';
        cell.className = 'unknown';
        cell.onclick = guess.bind(null, x, y);
      } else {
        cell.textContent = val;
      }
    }
  }

  if (msg.done) {
    done = true;
    clearInterval(timeInterval);
  }
  if (msg.message) {
    alert(msg.message);
  }
  if (msg.clear) {
    cellsToReset = msg.clear;
    resetCellsTimeout = setTimeout(resetCells, 1000);
    for (const pair of msg.clear) {
      // The cells that will be imminently cleared can still be clicked
      // even though they display non-?.
      const x = pair[0];
      const y = pair[1];
      const cell = document.querySelectorAll('#board tr')[y].children[x];
      cell.onclick = guess.bind(null, x, y);
    }
  }
  guessing = false;
}

document.addEventListener('DOMContentLoaded', function() {
  const protocol = window.location.protocol === 'https:' ? 'wss://' : 'ws://';
  ws = new WebSocket(protocol + window.location.host + '/ws');
  ws.onopen = onWsOpen;
  ws.onmessage = onResp;
});
