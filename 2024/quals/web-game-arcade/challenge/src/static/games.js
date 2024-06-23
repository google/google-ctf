/**
 * Copyright 2024 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

window.GAMES = [
  {
    name: "Asteroids",
    html: `<!DOCTYPE html>
    <html>
      <head>
      <meta charset="utf-8" />
      <title>Asteroids</title>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/p5.js/0.7.2/p5.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/p5.js/0.7.2/addons/p5.dom.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/p5.js/0.7.2/addons/p5.sound.min.js"></script>
        <style>html, body {
          margin: 0;
          padding: 0;
        }
        canvas {
          display: block;
        }
        </style>


      </head>
      <body>
        <script>
        /*
Iimplementation of the classic Atseroids game, made in Javasript using P5.js library, based on Dan Shiffman's "CodingChallenge" https://www.youtube.com/watch?v=hacZU523FyM

Use LEFT/RIGHT arrow to rotate the spaceship, UP arror to activate boost, SPACEBAR to fire. Collect green dots from exploded asteroids to augment shield level and gain temporary invulnerability (the ship turns green).
*/

var ship;
var asteroids = [];
var astnum;
var initastnum = 2;
var debris = [];
var energy = [];
var gameLevel = 0;
var message;

function setup() {
  createCanvas(windowWidth, windowHeight);
  textFont("Courier");
  ship = new Ship();
  initialize("let's play!", initastnum);
}

function draw() {
  background(0);
  for (var i = debris.length - 1; i >= 0; i--) {
    debris[i].update();
    debris[i].render();
    if (debris[i].transparency <= 0) {
      debris.splice(i, 1);
    }
  }

  for (var i = energy.length - 1; i >= 0; i--) {
    energy[i].update();
    energy[i].render();
    energy[i].edges();
    if (ship.hit(energy[i]) && !ship.safe) {
      ship.safe = true;
      setTimeout(function() {
        ship.safe = !ship.safe;
      }, 2000);
      ship.getBonus();
      energy[i].alive = false;
    };
    if (energy[i].life <= 20) {
      energy[i].alive = false;
    };
    if (!energy[i].alive) {
      energy.splice(i, 1);
    };
  }

  if (ship.alive) {
    ship.update();
    ship.render();
    ship.edges();
  } else {
    console.log("Game Over");
    message = "Game Over";
    //restart();
  };

  if (asteroids.length == 0) { // player cleared the level
    astnum += 3;
    initialize("You Win! Level up!", astnum);
  }

  for (var i = asteroids.length - 1; i >= 0; i--) {
    asteroids[i].render();
    asteroids[i].update();
    asteroids[i].edges();
    if (ship.hit(asteroids[i]) && !ship.safe) {
      ship.danger = true;
      setTimeout(function() {
        ship.danger = !ship.danger;
      }, 100);
      ship.getDamage(asteroids[i]);
      console.log("Damaging the shield " + ship.shieldLevel);
      asteroids[i].explode();
      asteroids.splice(i, 1);
      //console.log(asteroids.length);
      //ship.explode();
    }
  }

  //interface info
  ship.interface();
  }


  function initialize(messageText, newastnum) {
    message = messageText;
    gameLevel += 1;
    astnum = newastnum;
    basicinit();
  }

  function restart(messageText, newastnum) {
    ship.init();
    gameLevel = 1;
    asteroids = [];
    energy = [];
    message = messageText;
    astnum = newastnum;
    basicinit();
  }

  function basicinit() {
    for (var i = 0; i < astnum; i++) {
      asteroids.push(new Asteroid());
    }
    ship.shieldLevel == 100;
    ship.safe = true;
    setTimeout(function() {
      ship.safe = false;
      message = "";
    }, 4000);
  }


  function keyReleased() {
    if (keyCode == RIGHT_ARROW || keyCode == LEFT_ARROW) {
      ship.setRotation(0);
    } else if (keyCode == UP_ARROW) {
      ship.boosting = false;
    }
  }

  function keyPressed() {
    if (key == ' ') {
      ship.lasers.push(new Laser(ship.pos, ship.heading));
    } else if (keyCode == RIGHT_ARROW) {
      ship.setRotation(0.1);
    } else if (keyCode == LEFT_ARROW) {
      ship.setRotation(-0.1);
    } else if (keyCode == UP_ARROW) {
      ship.boosting = true;
    } else if (keyCode == ENTER && message == "Game Over") {
      console.log("DAMN!!");
      restart("let's play again!", initastnum);
    }
  }


function windowResized() {
    resizeCanvas(windowWidth, windowHeight);
}

/////// SHIP Class

function Ship() {
  this.pos = createVector(width / 2, height / 2 + 50);
  this.vel = createVector(0, 0);
  this.r = 10;
  this.heading = 0;
  this.rotation = 0;
  this.boosting = false;
  this.lasers = [];
  this.shieldLevel = 100;
  this.shieldMax = 200;
  this.alive = true;
  this.danger = false;
  this.safe = true;
  this.score = 0;
}

Ship.prototype.interface = function() {
  textSize(14);
  fill(255);
  noStroke();
  text("Score = " + this.score, 50, 50);
  //text("Shield = " + constrain(round(ship.shieldLevel), 0, 100), 50, 65);
  if (this.shieldLevel >= this.shieldMax) {
    text("Shield = Max!", 50, 65);
  } else {
    text("Shield = " + constrain(round(this.shieldLevel), 0, round(this.shieldLevel)), 50, 65);
  }
  text("Level = " + gameLevel, 50, 80);
  if (message) {
    textSize(32);
    text(message, width / 2 - message.length * 10, height / 2);
  }
}

Ship.prototype.init = function() {
  this.pos = createVector(width / 2, height / 2 + 50);
  this.vel = createVector(0, 0);
  ship.alive = true;
  ship.score = 0;
  ship.shieldLevel = 100;
}

Ship.prototype.hit = function(obj) {
  var d = dist(this.pos.x, this.pos.y, obj.pos.x, obj.pos.y);
  if (d < this.r + obj.r) {
    return true;
  } else {
    return false;
  }
}

Ship.prototype.getDamage = function(obj) {
  var damount = obj.r; // the bigger the object hitting the ship the heavier the damage amount
  this.shieldLevel -= damount;
  if (this.shieldLevel <= 0) {
    this.explode();
  }
}

Ship.prototype.getBonus = function() {
  this.shieldLevel += 30;
  this.score += 20;
  this.shieldLevel = constrain(this.shieldLevel, 0, this.shieldMax);
}

Ship.prototype.explode = function() {
  var debrisVel = p5.Vector.random2D().mult(random(0.5, 1.5));
  //var debrisVel = p5.Vector.add(this.lasers[i].vel.mult(0.2), asteroids[j].vel);
  var debrisNum = 50;
  generateDebris(this.pos, debrisVel, debrisNum); // handeling ship explosion
  this.alive = false;
}

Ship.prototype.update = function() {
  this.pos.add(this.vel);
  this.vel.mult(0.99); // simulating friction
  this.turn();
  if (this.boosting) {
    this.boost();
  }
  for (var i = this.lasers.length - 1; i >= 0; i--) {
    this.lasers[i].render();
    this.lasers[i].update();
    //console.log(this.lasers.length);
    if (this.lasers[i].offscreen()) { // cleaning up my laser beam array when beams are out off the screen
      this.lasers.splice(i, 1);
      //console.log(this.lasers.length);
    } else {
      for (var j = asteroids.length - 1; j >= 0; j--) {
        if (this.lasers[i].hits(asteroids[j])) {
          console.log("asteroid number " + j + " has been hitted! " + asteroids.length);
          var debrisVel = p5.Vector.add(this.lasers[i].vel.mult(0.2), asteroids[j].vel);
          var debrisNum = (asteroids[j].r) * 5;
          generateDebris(asteroids[j].pos, debrisVel, debrisNum); // handeling asteroids explosions
          var newAsteroids = asteroids[j].breakup(); // returns an array of two smaller asteroids
          if (newAsteroids.length > 0) {
            //console.log(newAsteroids);
            //asteroids.push(newAsteroids[0]); //asteroids.push(newAsteroids[1]);
            var probability = random() * 100;
            if (probability > 80) {
              //console.log("Shupershield!!!!");
              generateEnergy(asteroids[j].pos, debrisVel);
            }
            asteroids = asteroids.concat(newAsteroids); // concatenating (merging) arrays // https://www.w3schools.com/js/js_array_methods.asp
          } else {
            //update the score and do something else
            this.score += 10;
            console.log(this.score);
          }
          asteroids.splice(j, 1); // removing the hitted asteroid
          this.lasers.splice(i, 1); // removing the laser beam that hitted the target to prevent hitting the newly created smaller asteroids
          break; // exiting the loop to be safe not checking already removed stuff
        }
      }
    }
  }
}

Ship.prototype.boost = function() {
  var boostForce = p5.Vector.fromAngle(this.heading);
  boostForce.mult(0.1);
  this.vel.add(boostForce);
}

Ship.prototype.render = function() {
  push();
  translate(this.pos.x, this.pos.y);
  rotate(this.heading + PI / 2);
  fill(0);
  if (this.boosting) {
    console.log("bosting");
    stroke(255, 0, 0);
    line(-this.r + 3, this.r + 3, this.r - 3, this.r + 3);
  }
  if (this.danger) {
    stroke(255, 0, 0);
  } else if (this.safe) {
    stroke(0, 255, 0);
  } else {
    stroke(255);
  }
  triangle(-this.r, this.r, this.r, this.r, 0, -this.r);
  pop();
}

Ship.prototype.edges = function() {
  if (this.pos.x > width + this.r) {
    this.pos.x = -this.r;
  } else if (this.pos.x < -this.r) {
    this.pos.x = width + this.r;
  }
  if (this.pos.y > height + this.r) {
    this.pos.y = -this.r;
  } else if (this.pos.y < -this.r) {
    this.pos.y = height + this.r;
  }
}

Ship.prototype.setRotation = function(angle) {
  this.rotation = angle;
}

Ship.prototype.turn = function(angle) {
  this.heading += this.rotation;
}


////// LASER

function Laser(spos, angle) {
  this.pos = createVector(spos.x, spos.y);
  this.vel = p5.Vector.fromAngle(angle);
  this.vel.mult(10);
  this.r = 1;
}

// collision detection for asteroids and other eventual additional stuff
Laser.prototype.hits = function(target) {
  var d = dist(this.pos.x, this.pos.y, target.pos.x, target.pos.y);
  if(d < this.r + target.r){
    //console.log("hit!");
    return true;
  } else {
    return false;
  }
}

Laser.prototype.update = function() {
  this.pos.add(this.vel);
}

Laser.prototype.render = function() {
  push();
  strokeWeight(2);
  stroke(255);
  point(this.pos.x, this.pos.y);
  pop();
}

Laser.prototype.offscreen = function() {
  if (this.pos.x > width + this.r || this.pos.x < -this.r || this.pos.y > height + this.r || this.pos.y < -this.r) {
    return true;
  } else {
    return false;
  }
}


///// ENERGY

function Energy(pos, vel) {
  this.pos = pos.copy();
  this.vel = vel.copy();
  this.vel.mult(-0.2);
  //this.vel.add(p5.Vector.random2D().mult(-0.5));
  this.r = 10;
  this.life = random(100, 300);
  this.alive = true;

  this.update = function() {
    this.pos.add(this.vel);
    this.life -= 0.2;
  }

  this.render = function() {
    if (this.life > 20) {
      noFill();
      stroke(0, this.life, 0);
      ellipse(this.pos.x, this.pos.y, this.r, this.r);
    }
  }
}

Energy.prototype.edges = function() {
  if (this.pos.x > width + this.r) {
    this.pos.x = -this.r;
  } else if (this.pos.x < -this.r) {
    this.pos.x = width + this.r;
  }
  if (this.pos.y > height + this.r) {
    this.pos.y = -this.r;
  } else if (this.pos.y < -this.r) {
    this.pos.y = height + this.r;
  }
}

function generateEnergy(pos, vel) {
    energy.push(new Energy(pos, vel));
}


///// DEBRIS

function Debris(pos, vel) {
  this.pos = pos.copy();
  this.vel = vel.copy();
  this.vel.add(p5.Vector.random2D().mult(random(0.5, 1.5)));
  this.transparency = random(200, 255);

  this.update = function() {
    this.pos.add(this.vel);
    this.transparency -= 2;
  }

  this.render = function() {
    if (this.transparency > 0) {
      stroke(this.transparency);
      point(this.pos.x, this.pos.y);
    }
  }
}


function generateDebris(pos, vel, n) {
  for (var i = 0; i < n; i++) {
    debris.push(new Debris(pos, vel));
  }
}


///// ASTEROIDS

function Asteroid(pos, s) {
  if (pos) {
    this.pos = pos.copy();
  } else {
    this.pos = createVector(random(width), random(height));
  }
  this.vel = p5.Vector.random2D();
  this.sides = floor(random(15, 30));
  if (s) {
    this.sides = floor(s * 0.5);
  } else {
    this.sides = floor(random(15, 30));
  }
  this.rmin = 20;
  this.rmax = 40;
  this.r = map(this.sides, 15, 30, this.rmin, this.rmax);
  this.offset = [];
  for (var i = 0; i < this.sides; i++) {
    this.offset[i] = random(-5, 5); // alternative // -this.r/8, this.r/8
  }
  this.angle = 0;
  var increment = map(this.r, this.rmin, this.rmax, 0.1, 0.01);
  if (random() > 0.5) {
    this.increment = increment * -1;
  } else {
    this.increment = increment;
  }
}

Asteroid.prototype.explode = function() {
  //var debrisVel = p5.Vector.random2D().mult(random(0.5, 1.5));
  var debrisVel = this.vel.copy();
  var debrisNum = this.r * 5;
  generateDebris(this.pos, debrisVel, debrisNum); // handeling ship explosion
}

Asteroid.prototype.breakup = function() {
  var newA = [];
  if (this.sides > 5) {
    newA[0] = new Asteroid(this.pos, this.sides);
    newA[1] = new Asteroid(this.pos, this.sides);
  }
  return newA; // returning the array with my new asteroids
}

Asteroid.prototype.update = function() {
  this.pos.add(this.vel);
  this.angle += this.increment;
}

Asteroid.prototype.render = function() {
  push();
  translate(this.pos.x, this.pos.y);
  rotate(this.angle);
  noFill();
  stroke(255);
  //ellipse(0, 0, this.r*2, this.r*2);
  beginShape();
  for (var i = 0; i < this.sides; i++) {
    var angle = map(i, 0, this.sides, 0, TWO_PI);
    var r = this.r + this.offset[i];
    var x = r * cos(angle);
    var y = r * sin(angle);
    vertex(x, y);
  }
  endShape(CLOSE);
  pop();
}

Asteroid.prototype.edges = function() {
  if (this.pos.x > width + this.r) {
    this.pos.x = -this.r;
  } else if (this.pos.x < -this.r) {
    this.pos.x = width + this.r;
  }
  if (this.pos.y > height + this.r) {
    this.pos.y = -this.r;
  } else if (this.pos.y < -this.r) {
    this.pos.y = height + this.r;
  }
}

Asteroid.prototype.setRotation = function(angle) {
  this.rotation = angle;
}

Asteroid.prototype.turn = function(angle) {
  this.heading += this.rotation;
}
</script>
      </body>
    </html>
    `,
  },
  {
    name: "Password Game",
    metadata: {
      width: 642,
      height: 516,
    },
    html: `<html>
    <head>
      <meta charset=utf-8>
      <style>
        .correct{
          font-weight: 700;
          color: green;
        }
        .yellow{
          color: #e16a00;
          font-weight: 700;;
        }
        .nope{
          font-weight: 700;
        }
        #output span{
          margin-right:3px;
        }
      </style>
      <script>
        function getCookie(prop){
          const cookies = new Map();
          document.cookie.split(';').map(e=>e.split('=')).forEach(([a,c]) => {
            cookies.set(a.trim(),unescape(c));
          });
          return cookies.get(prop);
        }

        function savePassword(pwd){
          document.cookie = \`password=\${pwd}\`;
          localStorage.setItem('password', pwd)
          return pwd;
        }

        let password = getCookie('password') || localStorage.getItem('password') || "okoń";
        let correctPasswordSpan = document.createElement('span');
        correctPasswordSpan.classList.add('correct');
        correctPasswordSpan.innerHTML = password;
        let steps = 0;

        function changePwd(){
          steps = 0;
          password = passwordInp.value;
          correctPasswordSpan.innerHtml = password;
          output.innerHTML = 'Password changed.';
          savePassword(password);
        }

        function guessPassword(){
          steps++;
          const guess = guessInp.value;
          if(guess == password) {
            output.innerHTML = \`Congratulations, you guessed \${ correctPasswordSpan.outerHTML } in \${steps} steps! \`;
          }else if(guess.length < password.length){
            output.innerHTML = "Too short";
          }else if(guess.length > password.length){
            output.innerHTML = "Too long";
          }else {
            const pwd = password.split('');
            const gss = guess.split('');
            const unused = Array.from(pwd);

            const spans = [];
            for(let i=0; i<pwd.length; i++){
              const p = pwd[i], g = gss[i];
              if(p === g){
                unused.splice(unused.indexOf(g), 1);
                spans.push(\`<span class="correct">\${g}</span>\`);
              }else if(unused.includes(g)){
                spans.push(\`<span class="yellow">\${g}</span>\`);
              }else{
                spans.push(\`<span class="nope">\${g}</span>\`)
              }
            }
            output.innerHTML = spans.join('');
          }
        }
      </script>
    </head>
    <body>
      <h1>Password game</h1>
      Change password: <input id=passwordInp type=password> <button id=changePwdBtn onclick=changePwd()>change</button> <br>
      Guess password: <input id=guessInp> <button onclick=guessPassword()>guess</button><br>
      <pre><code id=output></code></pre>
    </body>
  </html>`,
  },
  {
    name: "Breakout!",
    metadata: {
      width: 642,
      height: 516,
    },
    html: `<!DOCTYPE html>
    <html lang="en">

    <head>
      <script src="https://cdnjs.cloudflare.com/ajax/libs/p5.js/1.1.9/p5.js"></script>
      <script src="https://cdnjs.cloudflare.com/ajax/libs/p5.js/1.1.9/addons/p5.sound.min.js"></script>
      <title>Password game</title>
      <style>
        html,
        body {
          margin: 0;
          padding: 0;
        }

        canvas {
          display: block;
        }
      </style>
      <meta charset="utf-8" />

    </head>

    <body>
      <script>
        class Paddle {
          constructor(x, y, w, h) {
            this.pos = createVector(x, y);
            this.vel = createVector(0, 0);
            this.width = w;
            this.height = h;
          }

          render() {
            push();
            strokeWeight(3);
            stroke("cadetblue");
            fill("greenyellow");
            rectMode(CENTER);
            rect(this.pos.x, this.pos.y, this.width, this.height);
            pop();
          }

          update() {
            this.pos.add(this.vel);

            if (this.pos.x > width + this.width / 2) {
              this.pos.x = -this.width / 2;
            } else if (this.pos.x < -this.width / 2) {
              this.pos.x = width + this.width / 2;
            }
          }

          setDir(dir) {
            this.vel.set(dir * 8, 0);
          }

          reset() {
            this.pos.x = width / 2;
          }

        }

        class Brick extends Paddle {
          constructor(x, y, w, h, points) {
            super(x, y, w, h);
            this.points = points;
          }

          render() {
            push();
            strokeWeight(2);
            if (this.points === 1) {
              stroke("orchid");
              fill("plum");
            } else if (this.points === 2) {
              stroke("indianred");
              fill("lightcoral");
            } else if (this.points === 3) {
              stroke("darkorange");
              fill("orange");
            } else if (this.points === 4) {
              stroke("gold");
              fill("yellow");
            } else if (this.points === 5) {
              stroke("chartreuse");
              fill("greenyellow");
            } else if (this.points === 6) {
              stroke("darkturquoise");
              fill("turquoise");
            } else if (this.points === 7) {
              stroke("steelblue");
              fill("cadetblue");
            }
            rectMode(CENTER);
            rect(this.pos.x, this.pos.y, this.width - 2, this.height - 2);
            textAlign(CENTER, CENTER);
            textSize(15);
            noStroke();
            fill(0);
            text(this.points, this.pos.x, this.pos.y);
            pop();
          }
        }

        class Ball {
          constructor(x, y) {
            this.pos = createVector(x, y);
            this.speed = 3;
            this.vel = createVector(this.speed, -this.speed);
            this.r = 7;
          }

          render() {
            push();
            strokeWeight(3);
            stroke("rebeccapurple");
            fill("crimson");
            circle(this.pos.x, this.pos.y, this.r * 2);
            pop();
          }

          update() {
            this.pos.add(this.vel);
          }

          colliding(brick) {
            if (this.pos.x + this.r < brick.pos.x - brick.width / 2) {
              return false;
            } else if (this.pos.x - this.r > brick.pos.x + brick.width / 2) {
              return false;
            } else if (this.pos.y + this.r < brick.pos.y - brick.height / 2) {
              return false;
            } else if (this.pos.y - this.r > brick.pos.y + brick.height / 2) {
              return false;
            } else {
              return true;
            }
          }

          bounceOff(brick) {
            this.vel.x *= -1;
            this.update();

            var prevVel = this.vel.copy();

            if (this.colliding(brick)) {
              //console.log("bounce");
              this.vel.x *= -1;
              this.vel.y *= -1;
            }
            this.pos.sub(prevVel);
          }

          edges() {
            if (this.pos.x > width - this.r) {
              this.pos.x = width - this.r;
              this.vel.x *= -1;
            } else if (this.pos.x < this.r) {
              this.pos.x = this.r;
              this.vel.x *= -1;
            } else if (this.pos.y < this.r) {
              this.pos.y = this.r;
              this.vel.y *= -1;
            }
          }

          bounce(paddle) {
            if (this.pos.x > paddle.pos.x - paddle.width / 2 && this.pos.x < paddle.pos.x + paddle.width / 2 && this.pos.y + this.r > paddle.pos.y - paddle.height / 2 && this.pos.y < paddle.pos.y) {
              let relativeX = map(this.pos.x, paddle.pos.x - paddle.width / 2, paddle.pos.x + paddle.width / 2, -1, 1);
              this.vel.set(relativeX * this.speed, -this.speed);
            }
          }

          end() {
            if (this.pos.y > height) {
              lives--;
              this.reset();
              paddle.reset();
            }
            if (lives <= 0) {
              gameOver = true;
              gameStarted = false;
            }
          }

          won() {
            if (bricks.length === 0) {
              gameWon = true;
              gameOver = false;
              gameStarted = false;
              gameInfo = false;
            }
          }

          reset() {
            this.pos.x = width / 2;
            this.pos.y = height - 94;
            this.vel.set(this.speed, -this.speed);
          }

        }

        let ball;
        let paddle;
        let bricks = [];
        let w, h;
        let gameStarted = false;
        let gameInfo = true;
        let gameOver = false;
        let gameWon = false;
        let score = 0;
        let lives = 3;

        function setup() {
          createCanvas(640, 480);

          ball = new Ball(width / 2, height - 94);
          paddle = new Paddle(width / 2, height - 80, 90, 12);

          createBricks(1);
        }

        function keyPressed() {
          if (keyCode === RIGHT_ARROW) {
            paddle.setDir(1);
          } else if (keyCode === LEFT_ARROW) {
            paddle.setDir(-1);
          }

          if (key == "1") {
            createBricks(1);
          } else if (key == "2") {
            createBricks(2);
          }

          if (keyCode === ENTER) {
            gameInfo = true;
            gameOver = false;
            gameStarted = false;
            gameWon = false;
            ball.reset();
            paddle.reset();
            createBricks(1);
            score = 0;
            lives = 3;
          }

          if (key === ' ') {
            gameStarted = true;
            gameInfo = false;
            gameWon = false;
            gameOver = false;
          }


        }

        function keyReleased() {
          paddle.setDir(0);
        }

        function draw() {
          const bkg = color("lightblue");
          background(red(bkg) / 2, green(bkg) / 2, blue(bkg) / 2);

          for (let i = 0; i < lives; i++) {
            fill("LightPink");
            stroke("DeepPink");
            strokeWeight(3);
            circle(i * 45 + 30, 35, 30);
          }

          textSize(30);
          fill("coral");
          stroke(0);
          strokeWeight(4);
          text("Score : " + score, width - 100, height / 4 - 80);
          strokeWeight(2);
          stroke("limegreen");
          text("Score : " + score, width - 100, height / 4 - 80);

          textSize(40);
          fill(255);
          strokeWeight(4);
          stroke("navy")
          text("Breakout Game!!", width / 2 - 10, height / 4 - 80);

          textSize(15);
          strokeWeight(2);
          fill("darkorange");
          text("by : Abhay and Simon!", width - 80, height - 20);

          for (let brick of bricks) {
            brick.render();
          }
          ball.render();
          paddle.render();
          ball.edges();
          ball.end();
          ball.won();

          if (gameInfo && !gameStarted && !gameOver && !gameWon) {
            textAlign(CENTER, CENTER);
            textSize(20);
            fill("LightGoldenRodYellow");
            strokeWeight(3);
            stroke(0);
            text("use the arrow keys to move the paddle", width / 2, height / 2);
            text("use 1 and 2 to toggle levels", width / 2, height / 2 + 25);
            fill("Khaki");
            text("Press Space to start the game!!", width / 2, height / 2 + 50);
            ball.pos.x = paddle.pos.x;
          }

          //ball.update();

          if (gameStarted && !gameInfo && !gameOver && !gameWon) {
            paddle.update();
            ball.update();
            ball.bounce(paddle);

            let ABBrick = false;
            for (let i = bricks.length - 1; i >= 0; i--) {
              let brick = bricks[i];
              if (ball.colliding(brick)) {
                if (ABBrick === false) {
                  ball.bounceOff(brick);
                  ABBrick = true;
                }
                score += brick.points;
                bricks.splice(i, 1);
              }
            }
          }

          if (gameOver && !gameStarted && !gameInfo && !gameWon) {
            fill("darkMagenta");
            textAlign(CENTER, CENTER);
            strokeWeight(5);
            stroke("firebrick");
            textSize(50);
            text("GAME IS OVER!!", width / 2, height / 2);
            fill("Khaki");
            textSize(20);
            text("press enter to play again!", width / 2, height / 2 + 75);
          }

          if (gameWon && !gameOver && !gameStarted && !gameInfo) {
            textAlign(CENTER, CENTER);
            textSize(70);
            stroke("Chartreuse");
            strokeWeight(6);
            fill("MediumSpringGreen");
            text("YOU WIN!!!!!", width / 2, height / 2);
            stroke(0);
            strokeWeight(3);
            text("YOU WIN!!!!!", width / 2, height / 2);
            fill("cyan");
            stroke(0);
            textSize(20);
            text("THAT WAS A GREAT ACHIVEMENT!!!", width / 2, height / 2 - 100);
            fill("Khaki");
            text("press enter to play again!", width / 2, height / 2 + 50);

          }

        }

        function createBricks(level) {
          if (level === 1) {
            bricks.splice(0);
            for (let i = 0; i < 14; i++) {
              for (let j = 0; j < 7; j++) {
                w = width / 14;
                h = 15;
                bricks.push(new Brick(i * w + w / 2, j * h + h / 2 + 75, w, h, 7 - j));
              }
            }
          } else if (level === 2) {
            bricks.splice(0);
            for (let j = 0; j < 14; j++) {
              for (let i = 0; i < j + 1; i++) {
                w = width / 14;
                h = 15;
                bricks.push(new Brick(i * w + w / 2, j * h + h / 2 + 75, w, h, (2 * (14 - i) - 1) % 8));
              }
            }
          }
        }
      </script>
    </body>

    </html>

  `,
  },
  {
    name: "Shooter",
    metadata: {
      width: 610,
      height: 610,
    },
    html: `<!DOCTYPE html>
    <html>

    <head>
      <script src="https://cdnjs.cloudflare.com/ajax/libs/p5.js/0.7.2/p5.min.js"></script>
      <script src="https://cdnjs.cloudflare.com/ajax/libs/p5.js/0.7.2/addons/p5.dom.min.js"></script>
      <script src="https://cdnjs.cloudflare.com/ajax/libs/p5.js/0.7.2/addons/p5.sound.min.js"></script>
      <meta charset="utf-8" />
      <style>
        html,
        body {
          margin: 0;
          padding: 0;
        }

        canvas {
          display: block;
        }
      </style>

    </head>

    <body>
      <script>
        let bulletsFired = [];
        let targetBalloons = [];
        let mainTurrent;
        let turPosX = 300;
        let turPosY = 300;
        let targetTimer = 0;
        let balloonSpawnMultiplier = 2;
        let balloonSizeMultiplier = 2;
        let score = 0;
        let Retry;

        let highScore = 0;


        function setup() {
          createCanvas(600, 600);
          angleMode(DEGREES);
          mainTurrent = new turrent(300, 300);
          Retry = createButton('retry');
          Retry.hide();

          if (!Cookies.get('highscore')) {
            Cookies.set('highscore', '0');
          }
          highScore = Cookies.get('highscore');
        }


        function mousePressed() {
          let mouseVector = getMouseVector();
          oneBullet = new bullet(mouseVector.x, mouseVector.y);
          bulletsFired.push(oneBullet);
        }

        function draw() {
          background(20);

          drawReticle();

          //----------------------------------------BALLOONS-SPAWN--------------------------------------
          targetTimer += 1;
          let spawnInterval = int(100 / balloonSpawnMultiplier);
          //print(spawnInterval)
          if (targetTimer % spawnInterval == 0) {
            let newBalloon = new balloon();
            targetBalloons.push(newBalloon);
            score += 5;
          }


          //----------------------------------------------BULLETS----------------------------------------
          for (var i = 0; i < bulletsFired.length; i++) {
            bulletsFired[i].display();
            bulletsFired[i].update();
            if (bulletsFired[i].outOfBounds()) {
              bulletsFired.splice(i, 1);
            }
            else if (bulletsFired[i].hitScan()) {
              bulletsFired.splice(i, 1);
            }
          }


          //-------------------------------------------EVIL-BALLOONS----------------------------------------
          for (var i = 0; i < targetBalloons.length; i++) {
            targetBalloons[i].display();
            targetBalloons[i].update();
            if (targetBalloons[i].outOfBounds()) {
              targetBalloons.splice(i, 1);
            }
          }

          balloonSpawnMultiplier += 0.001;
          if (balloonSizeMultiplier < 5) {
            balloonSizeMultiplier += 0.001;
          }

          //------------------------------------------HERO-AND-HERO-DED---------------------------------------a
          mainTurrent.display();
          mainTurrent.move();
          if (mainTurrent.hitScan()) {
            gameOver();
          }

          //------------------------------------------TUTORIAL------------------------------------------------
          noStroke();
          if (targetTimer < 500) {
            textAlign(LEFT);
            textFont('Helvetica');
            textSize(14);
            fill(235);
            text("arrow keys or wasd: move", 35, 35);
            text("mouse: aim", 35, 50);
            text("left click: fire", 35, 65);
          }
          fill(60);
          textAlign(CENTER);
          text("version 1.06 by carrefinho", 300, 580);
        }
        class bullet {
          constructor(xSpd, ySpd) {
            this.x = turPosX;
            this.y = turPosY;
            this.xSpd = 12 * xSpd;
            this.ySpd = 12 * ySpd;
          }

          display() {
            push()
            stroke(230, 255, 0);
            fill(230, 255, 0, 135);
            ellipse(this.x, this.y, 10);
            pop();
          }

          update() {
            this.x += this.xSpd;
            this.y += this.ySpd;
            this.xSpd *= 0.994;
            this.ySpd *= 0.994;
          }

          outOfBounds() {
            return (this.x > width + 10 || this.x < -10 || this.y > height + 10 || this.y < -10);
          }

          hitScan() {
            for (var i = 0; i < targetBalloons.length; i++) {
              var collideOrNot = collideCircleCircle(this.x, this.y, 10, targetBalloons[i].myX(), targetBalloons[i].myY(), targetBalloons[i].myR())
              if (collideOrNot) {
                targetBalloons.splice(i, 1);
                score += 1;
                return true;
              }
            }
            return false;
          }
        }
        class turrent {
          constructor() {
          }

          display() {
            push()
            stroke(230, 255, 0);
            fill(230, 255, 0);
            ellipse(turPosX, turPosY, 30);
            pop();
          }

          move() {
            if ((keyIsDown(65) || keyIsDown(LEFT_ARROW)) && turPosX > 5) {
              turPosX -= 2;
            }
            if ((keyIsDown(68) || keyIsDown(RIGHT_ARROW)) && turPosX < width - 5) {
              turPosX += 2;
            }
            if ((keyIsDown(87) || keyIsDown(UP_ARROW)) && turPosY > 5) {
              turPosY -= 2;
            }
            if ((keyIsDown(83) || keyIsDown(DOWN_ARROW)) && turPosY < height - 5) {
              turPosY += 2;
            }
          }

          hitScan() {
            for (var i = 0; i < targetBalloons.length; i++) {
              var collideOrNot = collideCircleCircle(turPosX, turPosY, 30, targetBalloons[i].myX(), targetBalloons[i].myY(), targetBalloons[i].myR())
              if (collideOrNot) {
                return true;
              }
            }
            return false;
          }
        }
        function getMouseVector() {
          let mouseXalt = mouseX - turPosX;
          let mouseYalt = mouseY - turPosY;
          let mouseDir = createVector(mouseXalt, mouseYalt);
          mouseDir.normalize();
          return mouseDir;
        }

        function drawReticle() {
          noFill();
          strokeWeight(1.5);
          stroke(0, 100, 125, 125);
          ellipse(mouseX, mouseY, 20);
          stroke(80, 160, 200, 125);
          line(mouseX - 14, mouseY - 14, mouseX + 14, mouseY + 14);
          line(mouseX + 14, mouseY - 14, mouseX - 14, mouseY + 14);
          stroke(80, 160, 200, 125);
          line(turPosX, turPosY, mouseX, mouseY);
        }

        function gameOver() {
          push()

          print("DED");
          noStroke();
          fill(20)
          rect(0, 200, 600, 200)

          textFont('Georgia');
          textAlign(CENTER);
          textSize(50);
          fill(170, 20, 20);
          text("YOU DIED", 300, 300)

          textFont('Helvetica');
          textSize(18);
          fill(235);
          let scoreString = "score: " + score;
          text(scoreString, 300, 340);

          if (score > highScore) {
            highScore = score;
            Cookies.remove('highscore');
            Cookies.set('highscore', highScore);
          }

          let highScoreString = "highscore: " + highScore;
          text(highScoreString, 300, 360);

          Retry.show();
          Retry.position(250, 380);
          Retry.size(100, 30);
          Retry.style('background-color', '#202020');
          Retry.style('color', '#FFFFFF');
          Retry.mousePressed(reset);

          pop();
          noLoop();

        }

        function reset() {
          Retry.hide();
          bulletsFired = [];
          targetBalloons = [];
          turPosX = 300;
          turPosY = 300;
          targetTimer = 0;
          balloonSpawnMultiplier = 2;
          balloonSizeMultiplier = 2;
          score = 0;

          loop();
        }
        class balloon {
          constructor() {
            this.side = int(random(4));
            switch (this.side) {
              case 0:
                this.x = 0;
                this.y = int(random(height));
                break;
              case 1:
                this.x = int(random(width));
                this.y = 0;
                break;
              case 2:
                this.x = width;
                this.y = int(random(height));
                break;
              case 3:
                this.x = int(random(width));
                this.y = height;
                break;
            }
            this.targetX = turPosX;
            this.targetY = turPosY;
            this.targetDir = createVector(this.targetX - this.x, this.targetY - this.y);
            this.targetDir.normalize();
            this.xSpd = this.targetDir.x * balloonSpawnMultiplier;
            this.ySpd = this.targetDir.y * balloonSpawnMultiplier;
            this.r = 12 * balloonSizeMultiplier;

          }

          display() {
            push();
            noStroke();
            fill(255, 0, 0);
            ellipse(this.x, this.y, this.r);
            pop();
          }

          update() {
            this.x += this.xSpd;
            this.y += this.ySpd;
          }

          outOfBounds() {
            return (this.x > width + 10 || this.x < -10 || this.y > height + 10 || this.y < -10);
          }

          myX() {
            return this.x;
          }

          myY() {
            return this.y;
          }

          myR() {
            return this.r;
          }


        }
        /*
        Created by http://benmoren.com
        Some functions and code modified version from http://www.jeffreythompson.org/collision-detection
        GNU LGPL 2.1 License
        Version 0.1 | January 10th, 2016
        */
        console.log("### p5.collide ###")

        p5.prototype._collideDebug = false;

        p5.prototype.collideDebug = function (debugMode) {
          _collideDebug = debugMode;
        }

        /*~++~+~+~++~+~++~++~+~+~ 2D ~+~+~++~+~++~+~+~+~+~+~+~+~+~+~+*/

        p5.prototype.collideRectRect = function (x, y, w, h, x2, y2, w2, h2) {
          //2d
          //add in a thing to detect rectMode CENTER
          if (x + w >= x2 &&    // r1 right edge past r2 left
            x <= x2 + w2 &&    // r1 left edge past r2 right
            y + h >= y2 &&    // r1 top edge past r2 bottom
            y <= y2 + h2) {    // r1 bottom edge past r2 top
            return true;
          }
          return false;
        };

        p5.prototype.collideRectCircle = function (rx, ry, rw, rh, cx, cy, diameter) {
          //2d
          // temporary variables to set edges for testing
          var testX = cx;
          var testY = cy;

          // which edge is closest?
          if (cx < rx) {
            testX = rx       // left edge
          } else if (cx > rx + rw) { testX = rx + rw }   // right edge

          if (cy < ry) {
            testY = ry       // top edge
          } else if (cy > ry + rh) { testY = ry + rh }   // bottom edge

          // // get distance from closest edges
          var distance = this.dist(cx, cy, testX, testY)

          // if the distance is less than the radius, collision!
          if (distance <= diameter / 2) {
            return true;
          }
          return false;
        };

        p5.prototype.collideCircleCircle = function (x, y, d, x2, y2, d2) {
          //2d
          if (this.dist(x, y, x2, y2) <= (d / 2) + (d2 / 2)) {
            return true;
          }
          return false;
        };

        p5.prototype.collidePointCircle = function (x, y, cx, cy, d) {
          //2d
          if (this.dist(x, y, cx, cy) <= d / 2) {
            return true;
          }
          return false;
        };

        p5.prototype.collidePointRect = function (pointX, pointY, x, y, xW, yW) {
          //2d
          if (pointX >= x &&         // right of the left edge AND
            pointX <= x + xW &&    // left of the right edge AND
            pointY >= y &&         // below the top AND
            pointY <= y + yW) {    // above the bottom
            return true;
          }
          return false;
        };

        p5.prototype.collidePointLine = function (px, py, x1, y1, x2, y2, buffer) {
          // get distance from the point to the two ends of the line
          var d1 = this.dist(px, py, x1, y1);
          var d2 = this.dist(px, py, x2, y2);

          // get the length of the line
          var lineLen = this.dist(x1, y1, x2, y2);

          // since floats are so minutely accurate, add a little buffer zone that will give collision
          if (buffer === undefined) { buffer = 0.1; }   // higher # = less accurate

          // if the two distances are equal to the line's length, the point is on the line!
          // note we use the buffer here to give a range, rather than one #
          if (d1 + d2 >= lineLen - buffer && d1 + d2 <= lineLen + buffer) {
            return true;
          }
          return false;
        }

        p5.prototype.collideLineCircle = function (x1, y1, x2, y2, cx, cy, diameter) {
          // is either end INSIDE the circle?
          // if so, return true immediately
          var inside1 = this.collidePointCircle(x1, y1, cx, cy, diameter);
          var inside2 = this.collidePointCircle(x2, y2, cx, cy, diameter);
          if (inside1 || inside2) return true;

          // get length of the line
          var distX = x1 - x2;
          var distY = y1 - y2;
          var len = this.sqrt((distX * distX) + (distY * distY));

          // get dot product of the line and circle
          var dot = (((cx - x1) * (x2 - x1)) + ((cy - y1) * (y2 - y1))) / this.pow(len, 2);

          // find the closest point on the line
          var closestX = x1 + (dot * (x2 - x1));
          var closestY = y1 + (dot * (y2 - y1));

          // is this point actually on the line segment?
          // if so keep going, but if not, return false
          var onSegment = this.collidePointLine(closestX, closestY, x1, y1, x2, y2);
          if (!onSegment) return false;

          // draw a debug circle at the closest point on the line
          if (this._collideDebug) {
            this.ellipse(closestX, closestY, 10, 10);
          }

          // get distance to closest point
          distX = closestX - cx;
          distY = closestY - cy;
          var distance = this.sqrt((distX * distX) + (distY * distY));

          if (distance <= diameter / 2) {
            return true;
          }
          return false;
        }

        p5.prototype.collideLineLine = function (x1, y1, x2, y2, x3, y3, x4, y4, calcIntersection) {

          var intersection;

          // calculate the distance to intersection point
          var uA = ((x4 - x3) * (y1 - y3) - (y4 - y3) * (x1 - x3)) / ((y4 - y3) * (x2 - x1) - (x4 - x3) * (y2 - y1));
          var uB = ((x2 - x1) * (y1 - y3) - (y2 - y1) * (x1 - x3)) / ((y4 - y3) * (x2 - x1) - (x4 - x3) * (y2 - y1));

          // if uA and uB are between 0-1, lines are colliding
          if (uA >= 0 && uA <= 1 && uB >= 0 && uB <= 1) {

            if (this._collideDebug || calcIntersection) {
              // calc the point where the lines meet
              var intersectionX = x1 + (uA * (x2 - x1));
              var intersectionY = y1 + (uA * (y2 - y1));
            }

            if (this._collideDebug) {
              this.ellipse(intersectionX, intersectionY, 10, 10);
            }

            if (calcIntersection) {
              intersection = {
                "x": intersectionX,
                "y": intersectionY
              }
              return intersection;
            } else {
              return true;
            }
          }
          if (calcIntersection) {
            intersection = {
              "x": false,
              "y": false
            }
            return intersection;
          }
          return false;
        }

        p5.prototype.collideLineRect = function (x1, y1, x2, y2, rx, ry, rw, rh, calcIntersection) {

          // check if the line has hit any of the rectangle's sides. uses the collideLineLine function above
          var left, right, top, bottom, intersection;

          if (calcIntersection) {
            left = this.collideLineLine(x1, y1, x2, y2, rx, ry, rx, ry + rh, true);
            right = this.collideLineLine(x1, y1, x2, y2, rx + rw, ry, rx + rw, ry + rh, true);
            top = this.collideLineLine(x1, y1, x2, y2, rx, ry, rx + rw, ry, true);
            bottom = this.collideLineLine(x1, y1, x2, y2, rx, ry + rh, rx + rw, ry + rh, true);
            intersection = {
              "left": left,
              "right": right,
              "top": top,
              "bottom": bottom
            }
          } else {
            //return booleans
            left = this.collideLineLine(x1, y1, x2, y2, rx, ry, rx, ry + rh);
            right = this.collideLineLine(x1, y1, x2, y2, rx + rw, ry, rx + rw, ry + rh);
            top = this.collideLineLine(x1, y1, x2, y2, rx, ry, rx + rw, ry);
            bottom = this.collideLineLine(x1, y1, x2, y2, rx, ry + rh, rx + rw, ry + rh);
          }

          // if ANY of the above are true, the line has hit the rectangle
          if (left || right || top || bottom) {
            if (calcIntersection) {
              return intersection;
            }
            return true;
          }
          return false;
        }


        p5.prototype.collidePointPoly = function (px, py, vertices) {
          var collision = false;

          // go through each of the vertices, plus the next vertex in the list
          var next = 0;
          for (var current = 0; current < vertices.length; current++) {

            // get next vertex in list if we've hit the end, wrap around to 0
            next = current + 1;
            if (next == vertices.length) next = 0;

            // get the PVectors at our current position this makes our if statement a little cleaner
            var vc = vertices[current];    // c for "current"
            var vn = vertices[next];       // n for "next"

            // compare position, flip 'collision' variable back and forth
            if (((vc.y > py && vn.y < py) || (vc.y < py && vn.y > py)) &&
              (px < (vn.x - vc.x) * (py - vc.y) / (vn.y - vc.y) + vc.x)) {
              collision = !collision;
            }
          }
          return collision;
        }

        // POLYGON/CIRCLE
        p5.prototype.collideCirclePoly = function (cx, cy, diameter, vertices, interior) {

          if (interior == undefined) {
            interior = false;
          }

          // go through each of the vertices, plus the next vertex in the list
          var next = 0;
          for (var current = 0; current < vertices.length; current++) {

            // get next vertex in list if we've hit the end, wrap around to 0
            next = current + 1;
            if (next == vertices.length) next = 0;

            // get the PVectors at our current position this makes our if statement a little cleaner
            var vc = vertices[current];    // c for "current"
            var vn = vertices[next];       // n for "next"

            // check for collision between the circle and a line formed between the two vertices
            var collision = this.collideLineCircle(vc.x, vc.y, vn.x, vn.y, cx, cy, diameter);
            if (collision) return true;
          }

          // test if the center of the circle is inside the polygon
          if (interior == true) {
            var centerInside = this.collidePointPoly(cx, cy, vertices);
            if (centerInside) return true;
          }

          // otherwise, after all that, return false
          return false;
        }

        p5.prototype.collideRectPoly = function (rx, ry, rw, rh, vertices, interior) {
          if (interior == undefined) {
            interior = false;
          }

          // go through each of the vertices, plus the next vertex in the list
          var next = 0;
          for (var current = 0; current < vertices.length; current++) {

            // get next vertex in list if we've hit the end, wrap around to 0
            next = current + 1;
            if (next == vertices.length) next = 0;

            // get the PVectors at our current position this makes our if statement a little cleaner
            var vc = vertices[current];    // c for "current"
            var vn = vertices[next];       // n for "next"

            // check against all four sides of the rectangle
            var collision = this.collideLineRect(vc.x, vc.y, vn.x, vn.y, rx, ry, rw, rh);
            if (collision) return true;

            // optional: test if the rectangle is INSIDE the polygon note that this iterates all sides of the polygon again, so only use this if you need to
            if (interior == true) {
              var inside = this.collidePointPoly(rx, ry, vertices);
              if (inside) return true;
            }
          }

          return false;
        }

        p5.prototype.collideLinePoly = function (x1, y1, x2, y2, vertices) {

          // go through each of the vertices, plus the next vertex in the list
          var next = 0;
          for (var current = 0; current < vertices.length; current++) {

            // get next vertex in list if we've hit the end, wrap around to 0
            next = current + 1;
            if (next == vertices.length) next = 0;

            // get the PVectors at our current position extract X/Y coordinates from each
            var x3 = vertices[current].x;
            var y3 = vertices[current].y;
            var x4 = vertices[next].x;
            var y4 = vertices[next].y;

            // do a Line/Line comparison if true, return 'true' immediately and stop testing (faster)
            var hit = this.collideLineLine(x1, y1, x2, y2, x3, y3, x4, y4);
            if (hit) {
              return true;
            }
          }
          // never got a hit
          return false;
        }

        p5.prototype.collidePolyPoly = function (p1, p2, interior) {
          if (interior == undefined) {
            interior = false;
          }

          // go through each of the vertices, plus the next vertex in the list
          var next = 0;
          for (var current = 0; current < p1.length; current++) {

            // get next vertex in list, if we've hit the end, wrap around to 0
            next = current + 1;
            if (next == p1.length) next = 0;

            // get the PVectors at our current position this makes our if statement a little cleaner
            var vc = p1[current];    // c for "current"
            var vn = p1[next];       // n for "next"

            //use these two points (a line) to compare to the other polygon's vertices using polyLine()
            var collision = this.collideLinePoly(vc.x, vc.y, vn.x, vn.y, p2);
            if (collision) return true;

            //check if the 2nd polygon is INSIDE the first
            if (interior == true) {
              collision = this.collidePointPoly(p2[0].x, p2[0].y, p1);
              if (collision) return true;
            }
          }

          return false;
        }

        p5.prototype.collidePointTriangle = function (px, py, x1, y1, x2, y2, x3, y3) {

          // get the area of the triangle
          var areaOrig = this.abs((x2 - x1) * (y3 - y1) - (x3 - x1) * (y2 - y1));

          // get the area of 3 triangles made between the point and the corners of the triangle
          var area1 = this.abs((x1 - px) * (y2 - py) - (x2 - px) * (y1 - py));
          var area2 = this.abs((x2 - px) * (y3 - py) - (x3 - px) * (y2 - py));
          var area3 = this.abs((x3 - px) * (y1 - py) - (x1 - px) * (y3 - py));

          // if the sum of the three areas equals the original, we're inside the triangle!
          if (area1 + area2 + area3 == areaOrig) {
            return true;
          }
          return false;
        }

        p5.prototype.collidePointPoint = function (x, y, x2, y2, buffer) {
          if (buffer == undefined) {
            buffer = 0;
          }

          if (this.dist(x, y, x2, y2) <= buffer) {
            return true;
          }

          return false;
        };

        p5.prototype.collidePointArc = function (px, py, ax, ay, arcRadius, arcHeading, arcAngle, buffer) {

          if (buffer == undefined) {
            buffer = 0;
          }
          // point
          var point = this.createVector(px, py);
          // arc center point
          var arcPos = this.createVector(ax, ay);
          // arc radius vector
          var radius = this.createVector(arcRadius, 0).rotate(arcHeading);

          var pointToArc = point.copy().sub(arcPos);

          if (point.dist(arcPos) <= (arcRadius + buffer)) {
            var dot = radius.dot(pointToArc);
            var angle = radius.angleBetween(pointToArc);
            if (dot > 0 && angle <= arcAngle / 2 && angle >= -arcAngle / 2) {
              return true;
            }
          }
          return false;
        }
          /*!
           * JavaScript Cookie v2.2.0
           * https://github.com/js-cookie/js-cookie
           *
           * Copyright 2006, 2015 Klaus Hartl & Fagner Brack
           * Released under the MIT license
           */
          ; (function (factory) {
            var registeredInModuleLoader = false;
            if (typeof define === 'function' && define.amd) {
              define(factory);
              registeredInModuleLoader = true;
            }
            if (typeof exports === 'object') {
              module.exports = factory();
              registeredInModuleLoader = true;
            }
            if (!registeredInModuleLoader) {
              var OldCookies = window.Cookies;
              var api = window.Cookies = factory();
              api.noConflict = function () {
                window.Cookies = OldCookies;
                return api;
              };
            }
          }(function () {
            function extend() {
              var i = 0;
              var result = {};
              for (; i < arguments.length; i++) {
                var attributes = arguments[i];
                for (var key in attributes) {
                  result[key] = attributes[key];
                }
              }
              return result;
            }

            function init(converter) {
              function api(key, value, attributes) {
                var result;
                if (typeof document === 'undefined') {
                  return;
                }

                // Write

                if (arguments.length > 1) {
                  attributes = extend({
                    path: '/'
                  }, api.defaults, attributes);

                  if (typeof attributes.expires === 'number') {
                    var expires = new Date();
                    expires.setMilliseconds(expires.getMilliseconds() + attributes.expires * 864e+5);
                    attributes.expires = expires;
                  }

                  // We're using "expires" because "max-age" is not supported by IE
                  attributes.expires = attributes.expires ? attributes.expires.toUTCString() : '';

                  try {
                    result = JSON.stringify(value);
                    if (/^[\{\[]/.test(result)) {
                      value = result;
                    }
                  } catch (e) { }

                  if (!converter.write) {
                    value = encodeURIComponent(String(value))
                      .replace(/%(23|24|26|2B|3A|3C|3E|3D|2F|3F|40|5B|5D|5E|60|7B|7D|7C)/g, decodeURIComponent);
                  } else {
                    value = converter.write(value, key);
                  }

                  key = encodeURIComponent(String(key));
                  key = key.replace(/%(23|24|26|2B|5E|60|7C)/g, decodeURIComponent);
                  key = key.replace(/[\(\)]/g, escape);

                  var stringifiedAttributes = '';

                  for (var attributeName in attributes) {
                    if (!attributes[attributeName]) {
                      continue;
                    }
                    stringifiedAttributes += '; ' + attributeName;
                    if (attributes[attributeName] === true) {
                      continue;
                    }
                    stringifiedAttributes += '=' + attributes[attributeName];
                  }
                  return (document.cookie = key + '=' + value + stringifiedAttributes);
                }

                // Read

                if (!key) {
                  result = {};
                }

                // To prevent the for loop in the first place assign an empty array
                // in case there are no cookies at all. Also prevents odd result when
                // calling "get()"
                var cookies = document.cookie ? document.cookie.split('; ') : [];
                var rdecode = /(%[0-9A-Z]{2})+/g;
                var i = 0;

                for (; i < cookies.length; i++) {
                  var parts = cookies[i].split('=');
                  var cookie = parts.slice(1).join('=');

                  if (!this.json && cookie.charAt(0) === '"') {
                    cookie = cookie.slice(1, -1);
                  }

                  try {
                    var name = parts[0].replace(rdecode, decodeURIComponent);
                    cookie = converter.read ?
                      converter.read(cookie, name) : converter(cookie, name) ||
                      cookie.replace(rdecode, decodeURIComponent);

                    if (this.json) {
                      try {
                        cookie = JSON.parse(cookie);
                      } catch (e) { }
                    }

                    if (key === name) {
                      result = cookie;
                      break;
                    }

                    if (!key) {
                      result[name] = cookie;
                    }
                  } catch (e) { }
                }

                return result;
              }

              api.set = api;
              api.get = function (key) {
                return api.call(api, key);
              };
              api.getJSON = function () {
                return api.apply({
                  json: true
                }, [].slice.call(arguments));
              };
              api.defaults = {};

              api.remove = function (key, attributes) {
                api(key, '', extend(attributes, {
                  expires: -1
                }));
              };

              api.withConverter = init;

              return api;
            }

            return init(function () { });
          }));

      </script>

    </body>

    </html>
    `,
  },
];
