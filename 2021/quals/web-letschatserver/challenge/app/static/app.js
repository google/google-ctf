/**
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
msgDomain = "//letschat-messages-web.2021.ctfcompetition.com"

$("#chatInput").keydown(function(evt) {
  if (evt.keyCode == 13) {
    if(evt.shiftKey) {
      // Multi line
    } else {
      evt.preventDefault();
      submitMessage();
    }
  }
});

function logout() {
  app.logout();
  window.location.reload();
  debugger;
}

function addError(msg) {
  app.addRoom("Errors").addMessage(`System:${msg}`);
}

$("#newRoomBtn").click(function() {
  dialog("Enter room name", newRoom, function(){});
});
function newRoom(name) {
  $.post( "/newroom", {"roomName": name})
    .done(function() {
      app.addRoom(name);
      app.startRoom(name);
    })
    .fail(function(data) {
      dialogMessage(data.responseText);
    });
}

function joinRoom(name) {
  $.post( "/joinroom", {"roomName": name})
    .done(function() {
      app.addRoom(name)
    })
    .fail(function(data) {
      dialogMessage(data.responseText);
    });
}
$("#joinRoomBtn").click(function() {
  dialog("Enter room name", joinRoom, function(){})
});

function submitMessage() {
  to = app.currentRoom();
  if(! to) {
    dialogMessage("select a room first!");
    return;
  }
  let msg = $("#chatInput").val();
  if(msg == "") {
    return;
  }
  $("#chatInput").val("");
  $.post( "/message", {"to": to.name, "message": msg })
    .fail(function(data) {
      addError(`Error sending message: ${data.responseText}`);
    });
}

function toggleRegister() {
  $("#registerFrm").toggleClass("hidden", 500);
  $("#loginFrm").toggleClass("hidden", 500);
}

function register(token) {
  let u = $("#regUsername").val();
  let p = $("#regPassword").val();
  $.post( "/register", {"username": u, "password": p,"token":token })
  .done(function(data) {
    dialogMessage("Successfully registered!");
    toggleRegister();
  })
  .fail(function(data) {
    $("#registerError").text(data.responseText);
  })
}

function inviteCode() {
  let c = $("#inviteCode").val();
  $.post( "/invitecode", {"code": c})
  .done(function(data) {
    $("#invite").hide()
  })
  .fail(function(data) {
    alert("You tried to guess it! tsk tsk tsk")
  })
}



function login() {
  let u = $("#username").val();
  let p = $("#password").val();
  $.post( "/login", {"username": u, "password": p})
  .done(function(data) {
    app.successfulLogin(data, u);
  })
  .fail(function(data) {
    $("#loginError").text(data.responseText);
  })
}



function dialogMessage(message) {
  let container = $("<div>");
  let d = $("<div>");
  let m = $("<p>");
  let ok = $("<button>Ok</button>");

  m.text(message);
  ok.click(function() {
    container.fadeOut(300, function() { $(this).remove(); });
    d.fadeOut(300, function() { $(this).remove(); });
  });

  d.addClass("dialog");
  container.addClass("dialogContainer");
  d.append(m,ok);
  $("body").append(container,d);
  d.fadeIn();
  ok.focus();
}

function confirm(message, okCallback, cancelCallback) {
  let container = $("<div>");
  let d = $("<div>");
  let m = $("<p>");
  let ok = $("<button>Ok</button>");
  let cancel = $("<button>Cancel</button>");

  wrappedCallback = function() {
    d.fadeOut(300, function() { $(this).remove(); });
    container.fadeOut(300, function() { $(this).remove(); });
    okCallback();
  };

  m.text(message);
  ok.click(wrappedCallback);
  cancel.click(function() {
    container.fadeOut(300, function() { $(this).remove(); });
    d.fadeOut(300, function() { $(this).remove(); });
    cancelCallback();
  });

  d.addClass("dialog");
  container.addClass("dialogContainer");
  d.append(m,ok,cancel);
  $("body").append(container,d);
  d.fadeIn();
}


function dialog(message, okCallback, cancelCallback) {
  let container = $("<div>");
  let d = $("<div>");
  let m = $("<p>");
  let i = $("<input>");
  let ok = $("<button>Ok</button>");
  let cancel = $("<button>Cancel</button>");

  wrappedCallback = function() {
    d.fadeOut(300, function() { $(this).remove(); });
    container.fadeOut(300, function() { $(this).remove(); });
    okCallback(i.val());
  };

  i.keydown(function(evt) {
  if (evt.keyCode == 13) {
      evt.preventDefault();
      wrappedCallback();
    }
  });

  m.text(message);
  ok.click(wrappedCallback);
  cancel.click(function() {
    container.fadeOut(300, function() { $(this).remove(); });
    d.fadeOut(300, function() { $(this).remove(); });
    cancelCallback();
  });

  d.addClass("dialog");
  container.addClass("dialogContainer");
  d.append(m,i,ok,cancel);
  $("body").append(container,d);
  d.fadeIn();
  i.focus();
}


class App {

  constructor() {
    this.userId = localStorage.getItem("id");
    this.userName = localStorage.getItem("name");
    if(this.userId) {
      this.initialise();
    }
    this.room = false;
    this.rooms = {};
    this.lastMessages = {};
    this.roomCount = 1;
  }

  logout() {
    localStorage.removeItem("id");
    localStorage.removeItem("name");
  }

  setLastMessage(id, room) {
    this.lastMessages[room] = id;
  }

  Id() {
    return this.userId;
  }

  successfulLogin(userId, userName) {
    this.userName = userName;
    $("#userDetails").text(userName);
    localStorage.setItem("id",userId);
    localStorage.setItem("name",userName);
    this.userId = userId;
    this.initialise();
  }

  initialise() {
    $("#invite").hide();
    $("#login").hide();
    $("#userDetails").text(this.userName);
    this.getRooms();
    this.emptyRoom();
  }

  getRooms() {
    let that = this;
    return $.get( "/getrooms")
        .done(function(data){
          let rooms = data.split(",");
          for(let i = 0; i < rooms.length; i++) {
            that.addRoom(rooms[i]);
          }
          that.poll();
        })
        .fail(function(data){
            dialogMessage(`Error getting rooms. Try refreshing the page: ${data.responseText}`);
        });
  }

  allRoomNames() {
    let names = [];
    for(let room in this.rooms) {
      if (this.rooms.hasOwnProperty(room)) {
        if(room == "Errors") {
          continue;
        }
        names.push(room);
      }
    }
    return names;
  }

  poll() {
    let roomNames = this.allRoomNames();
    if(roomNames.lenght == 0) {
      return;
    }
    let that = this;
    let roomNameAndLastMessage = [];
    for(let i = 0; i < roomNames.length; i++) {
      roomNameAndLastMessage.push(`${roomNames[i]}:${this.lastMessages[roomNames[i]]}`)
    }
    $.post( "/poll",{"rooms":roomNameAndLastMessage.join(",")})
    .done(function(data) {
      for (let room in data) {
        if (room && data.hasOwnProperty(room)) {
          let r = that.addRoom(room);
          r.addMessages(data[room],room);
        }
      }
    })
    .fail(function(data) {
      addError(`Poll failure: ${data.responseText}`);
    })
    .always(function() {
      setTimeout(that.poll.bind(that), 3000);
    });
  }

  currentRoom() {
    return this.room;
  }
  hasRoom(name) {
    return this.rooms[name];
  }

  addRoom(name) {
    if(name == "") {
      return;
    }
    if(this.hasRoom(name)) {
      return this.rooms[name];
    }
    let r = new Room(name);
    this.rooms[name] = r;
    $("#roomsList").append(r.roomDiv());
    return r
  }

  startRoom(name) {
    if(this.rooms[name]) {
      this.room = this.rooms[name];
      this.rooms[name].start();
      $("#chatInput").prop("disabled",false);

    }
  }

  setRoomButtons() {
    $("#joinRoomBtn").prop("disabled",(this.roomCount > 9));
    $("#newRoomBtn").prop("disabled",(this.roomCount > 9));
  }

  emptyRoom() {
    $("#chatInput").prop("disabled",true);
    $("#chat").html("<h1>The database is reset every 48 hours so that this challenge can remain online indefinately. You will need to re-create your login etc. every 48 hours.</h1><p>Create a room and invite your friends!<p>Or ask your friends to invite you to their room and Join it</p><p>Don't have any friends? No worries! Everyone can join the 'public' room!</p>");
  }

  removeRoom(name) {
    this.roomCount--;
    this.setRoomButtons();
    this.rooms[name].remove();
    delete this.rooms[name];
    if(this.currentRoom() && this.currentRoom().name == name) {
      this.emptyRoom();
    }
  }
}

class Room {
  constructor(name) {
    this.name = name;
    this.messages = [];
    this.ids = {};
    this.queue = [];
    this.requests = 0;
  }

  remove() {
    this.containerEle.remove();
  }
  roomDiv() {
    let c = $("<div>");
    let p = $("<p>");
    let n = $("<a>");
    let i = $("<button>+ invite</button>");
    let l = $("<button>- leave</button>");

    this.nameEle = n;
    this.containerEle = c;

    p.append(n);

    n.text(this.name);
    let thatName = this.name;
    p.click(function() {
      app.startRoom(thatName);
    });
    i.click(this.invite.bind(this));
    l.click(this.leave.bind(this));
    if(this.name == "Errors") {
      c.append(p, $("<hr>"));
    } else {
      p.append(i,l)
      c.append(p,$("<hr>"));
    }
    c.addClass("roomMenuItem");

    return c;
  }

  invite() {
    dialog("enter username of who to invite", this.inviteCallback.bind(this), function(){});
  }

  inviteCallback2(userId) {
    $.post( "/inviteroom", {"toInvite": userId, "roomName": this.name})
      .done(function(id) {
        dialogMessage(`Invite success`);
      })
      .fail(function(data) {
        dialogMessage(`Error inviting user: ${data.responseText}`);
      });
  }

  inviteCallback(user) {
    let that = this;
    $.post( "/user", {"username": user})
      .done(function(id) {
        that.inviteCallback2(id);
      })
      .fail(function(data) {
        dialogMessage(`Unable to get ID for user "${user}": ${data.responseText}`);
      });
  }

  leave() {
    confirm("Are you sure you want to leave?", this.leaveDo.bind(this), function(){});
  }

  leaveDo() {
    let name = this.name;
    $.post( "/leaveroom", {"roomName": name})
      .done(function() {
        app.removeRoom(name);
      })
      .fail(function(data) {
        dialogMessage(`Unable to leave room: ${data.responseText}`);
      });
  }

  addMessages(msgs, room) {
    let lastMessage;
    for(let i = 0; i < msgs.length; i++) {
      if(this.ids[msgs[i]]) {
        continue;
      }
      lastMessage = msgs[i];
      this.ids[msgs[i]] = true;
      this.queue.push(msgs[i])
    }
    if(lastMessage) {
      app.setLastMessage(lastMessage, room);
      this.dequeue()
    }
  }

  async dequeue() {
    if(this.requests > 5) {
      return;
    }
    let todo = this.queue.shift()
    if(todo) {
      this.requests++;
      this.dequeue();

      let that = this;
      await $.get(`${msgDomain}/${todo}`)
        .done(function(msg) {
          that.addMessage(msg);
        })
        .fail(function(data) {
          addError(`Unable to retrieve message ${todo}: ${data.responseText}`);
        })
        .always(function() {
          that.requests--;
          that.dequeue();
        }).catch(e => {
          that.requests--;
          that.dequeue();
        });
    }
  }

  addMessage(msg) {
    this.messages.push(msg);
    if(app.currentRoom() == this ) {
      this.showMessage(msg);
    } else {
      this.nameEle.addClass("unread")
    }
  }

  showMessage(msg) {
    let c = $("<div>");
    let u = $("<div>");
    let m = $("<div>");
    c.addClass("messageContainer");
    u.addClass("messageUser");
    m.addClass("messageMessage");
    let [user, ...messageParts] = msg.split(/:(.*)/);
    m.text(messageParts.join(":").slice(0, -1));

    if(user == `Player${app.Id().split("-")[0]}`) {
      u.addClass("meUser");
      user = "Me";
    }
    if(user.startsWith("Player")) {
      u.addClass("playerUser");
    }
    if(user.startsWith("System")) {
      u.addClass("systemUser");
    }
    u.text("<" + user + ">");
    c.append(u,m);
    $("#chat").prepend(c);
  }


  start() {
    $("#chat").html("");
    $("#chatTitle").text(this.name);
    for(let i = 0; i < this.messages.length; i++) {
      this.showMessage(this.messages[i]);
    }
    this.nameEle.removeClass("unread");
  }
}

let app = new App();
