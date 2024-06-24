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

const express = require("express");
const fileUpload = require("express-fileupload");
const app = express();
const nanoid = require("nanoid");
const needle = require("needle");
const { Sequelize, DataTypes } = require("sequelize");
const bot = require("./bot.js");
const isNum = require("is-number");
const DB_HOST = process.env.DB_HOST;
const DB_USER = process.env.DB_USER;
const DB_PASS = process.env.DB_PASS;

/* 
 * NOTE TO PLAYERS: if running locally, install sqlite manually and replace the below with:
 * const sequelize = new Sequelize("sqlite::memory:");
 */

const sequelize = new Sequelize("grandprix", DB_USER, DB_PASS, {
  host: DB_HOST,
  dialect: "postgres",
});

const TEMPLATE_SERVER = "http://localhost:9999";
const BOUNDARY = "GP_HEAVEN";

const TEMPLATE_PIECES = [
  "head_end",
  "csp",
  "upload_form",
  "footer",
  "retrieve",
  "apiparser", /* We've deprecated the mediaparser. apiparser only! */
  "faves",
  "index",
];

const Configuration = sequelize.define("Configuration", {
  public_id: { type: DataTypes.STRING, primaryKey: true },
  year: DataTypes.INTEGER,
  make: DataTypes.STRING,
  model: DataTypes.STRING,
  custom: DataTypes.STRING,
  img_id: DataTypes.STRING,
});

const Media = sequelize.define("Media", {
  public_id: { type: DataTypes.STRING, primaryKey: true },
  img: DataTypes.BLOB("long"),
});

app.use(express.static(__dirname + "/public"));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(fileUpload({
	limits: { fileSize: 1 * 1024 * 1024 }
}));

// add a default car!
async function addADefaultCar() {
  await Configuration.upsert({
    year: "1967",
    make: "COSWORTH",
    model: "DFV",
    custom: "",
    public_id: "dfv",
    img_id: "default",
  });
}

app.get("/", async (req, res) => {
  try {
    var data = {
      0: "csp",
      1: "head_end",
      2: "index",
      3: "footer",
    };
    await needle.post(
      TEMPLATE_SERVER,
      data,
      { multipart: true, boundary: BOUNDARY },
      function (err, resp, body) {
        if (err) throw new Error(err);
        return res.send(body);
      }
    );
  } catch (e) {
    console.log(`ERROR IN /:\n${e}`);
    return res.status(500).json({ error: "error" });
  }
});

app.get("/fave", (req, res) => {
  return res.redirect(`/fave/dfv?F1=dfv`);
});

app.get("/fave/:GrandPrixHeaven", async (req, res) => {
  const grandPrix = await Configuration.findOne({
    where: { public_id: req.params.GrandPrixHeaven },
  });
  if (!grandPrix) return res.status(400).json({ error: "ERROR: ID not found" });
  let defaultData = {
    0: "csp",
    1: "retrieve",
    2: "apiparser",
    3: "head_end",
    4: "faves",
    5: "footer",
  };
  let needleBody = defaultData;
  if (grandPrix.custom != "") {
    try {
      needleBody = JSON.parse(grandPrix.custom);
      for (const [k, v] of Object.entries(needleBody)) {
        if (!TEMPLATE_PIECES.includes(v.toLowerCase()) || !isNum(parseInt(k)) || typeof(v) == 'object')
          throw new Error("invalid template piece");
        // don't be sneaky. We need a CSP!
        if (parseInt(k) == 0 && v != "csp") throw new Error("No CSP");
      }
    } catch (e) {
      console.log(`ERROR IN /fave/:GrandPrixHeaven:\n${e}`);
      return res.status(400).json({ error: "invalid custom body" });
    }
  }
  needle.post(
    TEMPLATE_SERVER,
    needleBody,
    { multipart: true, boundary: BOUNDARY },
    function (err, resp, body) {
      if (err) {
        console.log(`ERROR IN /fave/:GrandPrixHeaven:\n${e}`);
        return res.status(500).json({ error: "error" });
      }
      return res.status(200).send(body);
    }
  );
});

app.get("/new-fave", (req, res) => {
  var data = {
    0: "csp",
    1: "head_end",
    3: "upload_form",
    4: "footer",
  };
  needle.post(
    TEMPLATE_SERVER,
    data,
    { multipart: true, boundary: BOUNDARY },
    function (err, resp, body) {
      if (err) return res.status(500).json({ error: "error" });
      return res.status(200).send(body);
    }
  );
});

app.post("/api/new-car", async (req, res) => {
  let response = {
    img_id: "",
    config_id: "",
  };
  try {
    if (req.files && req.files.image) {
      const reqImg = req.files.image;
      if (reqImg.mimetype !== "image/jpeg") throw new Error("wrong mimetype");
      let request_img = reqImg.data;
      let saved_img = await Media.create({
        img: request_img,
        public_id: nanoid.nanoid(),
      });
      response.img_id = saved_img.public_id;
    }
    let custom = req.body.custom || "";
    let saved_config = await Configuration.create({
      year: req.body.year,
      make: req.body.make,
      model: req.body.model,
      custom: custom,
      public_id: nanoid.nanoid(),
      img_id: response.img_id
    });
    response.config_id = saved_config.public_id;
    return res.redirect(`/fave/${response.config_id}?F1=${response.config_id}`);
  } catch (e) {
    console.log(`ERROR IN /api/new-car:\n${e}`);
    return res.status(400).json({ error: "An error occurred" });
  }
});

app.get("/api/get-car/:carId", async (req, res) => {
  let carId = req.params.carId;
  try {
    const car = await Configuration.findOne({ where: { public_id: carId } });
    return res.status(200).json(car);
  } catch (e) {
    console.log(`ERROR IN /api/get-car/:carId:\n${e}`);
    return res.status(400).json({ error: "error" });
  }
});

app.get("/media/default", async (req, res) => {
  return res.redirect('/image/ferrari.jpeg');
});

app.get("/media/:mediaId", async (req, res) => {
  try {
    if (!req.params.mediaId) throw new Error("No mediaId");
    let mediaId = req.params.mediaId;
    const media = await Media.findOne({ where: { public_id: mediaId } });
    const imageBlob = media.img;
    res.set("content-type", "image/jpeg");
    return res.status(200).send(imageBlob);
  } catch (e) {
    console.log(`ERROR IN /media/:mediaId:\n${e}`);
    return res.status(400).json({ error: "error" });
  }
});

app.post("/report", async (req, res) => {
  const url = req.body.url;
  if (typeof url !== "string" || !url.startsWith('https://grandprixheaven-web.2024.ctfcompetition.com/')) {
    res.status(200).send("invalid url").end();
    return;
  }
  bot.visit(url);
  res.send("Done!").end();
});

app.get("*", (req, res) => {
  return res.status(404).json({ error: "Page not found" });
});

const PORT = process.env.PORT || 1337;
app.listen(PORT, async () => {
  console.log(`${new Date()}: Node server listening on port ${PORT}`);
  try {
    await sequelize.authenticate();
    await Configuration.sync();
    await Media.sync();
    await addADefaultCar();
    console.log("Database connection has been established successfully.");
  } catch (error) {
    console.error("Unable to connect to the database:", error);
  }
});
