// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

'use strict';

const cookieParser = require('cookie-parser');
const csp  = require('express-csp-header');
const crypto = require('crypto');
const express = require('express');
const fileUpload = require('express-fileupload')
const jsZip = require('jszip');
const urlBase64 = require('urlsafe-base64');

const sgtPepperTaunt = {message:'Wanna show me what you got!?!'};
const invalidLinkResponse = {message:"What's that? It's not https://saber-ninja.web.ctfcompetition.com/preview/*"};
const notPlayTestedResponse = {message:"That song hasn't been play-tested. Take the ID {id} to the play-testing room!"};
const neatResponse = {message:"Wow neat! I'll try to dance it"};
const isLinkRegex = /^https?:\/\//;
const isSaberRegex = /^https?:\/\/(saber\.ninja|saber-ninja\.web\.ctfcompetition\.com|bsaber-whv0d1d7jgejewe4-dot-ctf-web-kuqo48d\.appspot\.com|localhost:\d+)\/preview\/([-_a-zA-Z0-9]+)/;
const app = express();
app.enable('trust proxy');

app.use(csp({
  policies: {
    'default-src': [csp.SELF],
    'frame-src': ['*'],
  }
}));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  next();
})
app.use(express.static('static'))
app.use(express.urlencoded())
app.use(express.json())
app.use(cookieParser());
app.use(fileUpload({
  limits: { fileSize: 1024 * 1024 },
}));

// Secrets that must not be leaked to the players.
const CLIENT_AUTH_COOKIE = 'OjqMr0fkzn7xDghmf91x3SdVERtVbfhEWq2ZuUk+pTQ';
const XSSBOT_AUTH_COOKIE = 'hmJD+gAXgnewTFKXx5obnTTGHO1uGo/KfHWkU1wUGzs';

const SALTANDPEPPER_UPLOAD = {
  'id': 'ntSPPySYAwN0W5YbUje4Ww',
  'name': 'Fixing a Hole',
  'song': 'Fixing a Hole (CTF Remix)',
  'artist': 'CTF{ThoUGhtHEHoLesWereRathersMaLLtHeYHadtOCOUNTtHEmall}',
  'playTested': false,
  'uploader': 'sgt-pepper',
};

// By default, the client will authenticate using the service account file
// specified by the GOOGLE_APPLICATION_CREDENTIALS environment variable and use
// the project specified by the GOOGLE_CLOUD_PROJECT environment variable. See
// https://github.com/GoogleCloudPlatform/google-cloud-node/blob/master/docs/authentication.md
// These environment variables are set automatically on Google App Engine
const {Datastore} = require('@google-cloud/datastore');
const {PubSub} = require('@google-cloud/pubsub');

// Instantiate clients
const datastore = new Datastore();
const pubsub = new PubSub();

const upsertLevel = async (level) => {
  const key = level.key || datastore.key(['Level', level.id]);
  await datastore.save({
    key: key,
    data: level,
    excludeFromIndexes: [
      // All except owner
      'id', // id is already part of the key.
      'bundle',
      'name',
      'song',
      'artist',
      'playTested',
      'songFilename',
      'coverFilename',
      'beatmapFilename',
      'beatsPerMinute',
    ],
  });
};

const loadLevel = async (id) => {
  const key = datastore.key(['Level', id]);
  const results = await datastore.get(key);
  return results[0];
};

const loadOwnedLevels = async (owner) => {
  if (owner == XSSBOT_AUTH_COOKIE) {
    return [SALTANDPEPPER_UPLOAD];
  }
  // TODO: Use projection to avoid loading the bundle property.
  const query = datastore
    .createQuery('Level')
    .filter('owner', '=', owner)
    .limit(10);
  const results = await datastore.runQuery(query);
  return results[0];
};

const imageFilenameToMime = (filename) => {
  const extToMime = {
    'jpeg': 'image/jpeg',
    'jpg': 'image/jpeg',
    'png': 'image/png',
  }

  const parts = filename.split('.');
  const ext = parts[parts.length - 1];
  if (extToMime[ext]) {
    return extToMime[ext];
  }
  return null;
};

const audioFilenameToMime = (filename) => {
  const extToMime = {
    'egg': 'audio/ogg',
    'ogg': 'audio/ogg',
    'oga': 'audio/ogg',
    'wav': 'audio/wav',
  };

  const parts = filename.split('.');
  const ext = parts[parts.length - 1];
  if (extToMime[ext]) {
    return extToMime[ext];
  }
  return null;
}

app.post('/upload', async (req, res, next) => {
  if (!req.files || Object.keys(req.files).length == 0) {
    return res.status(400).send('No bundle was uploaded.').end();
  }
  const upload = req.files.bundle;
  if (upload.size >= 980000) {
    return res
        .status(400)
        .send('980KB limit - sorry, we\'re working on it! '
            + 'Try making a new map for the example or downsampling your own song.')
        .end();
  }
  const hasTraversal = (value) => value.includes("..");
  if (hasTraversal(upload.name)) {
    return res.status(400).send('Invalid filename').end();
  }
  const zip = await jsZip.loadAsync(upload.data);
  if (zip.filter((relativePath) => hasTraversal(relativePath)).length > 0) {
    return res.status(400).send('Invalid filename').end();
  }

  const dat = zip.file('Info.dat');
  if (!dat) {
    return res.status(400).send('Missing Info.dat in bundle.').end();
  }
  let info;
  try {
    info = JSON.parse(await dat.async('text'));
  } catch (error) {
    return res.status(400).send('Invalid format in Info.dat.').end();
  }
  const isString = (value) => typeof value == 'string';
  if (!isString(info._songFilename)
      || typeof info._beatsPerMinute != 'number'
      || !info._difficultyBeatmapSets
      || !info._difficultyBeatmapSets[0]
      || !info._difficultyBeatmapSets[0]._difficultyBeatmaps
      || !info._difficultyBeatmapSets[0]._difficultyBeatmaps[0]
      || !isString(info._difficultyBeatmapSets[0]._difficultyBeatmaps[0]._beatmapFilename)) {
    return res.status(400).send('Missing fields in Info.dat').end();
  }
  const hasCoverImage = isString(info._coverImageFilename) && info._coverImageFilename.length > 0;
  if (!audioFilenameToMime(info._songFilename)) {
    return res.status(400).send('Unsupported audio format').end();
  }
  if (hasCoverImage && !imageFilenameToMime(info._coverImageFilename)) {
    return res.status(400).send('Unsupported cover image format').end();
  }
  // Basic validation - make sure other files referenced by Info.dat exist.
  const missingEntries = [];
  const requireEntry = async (filename) => {
    const f = await zip.file(filename);
    if (f == null) {
      missingEntries.push(filename);
    }
    return f;
  };
  await requireEntry(info._songFilename);
  if(hasCoverImage){
   await requireEntry(info._coverImageFilename);
  }
  for (let beatmapSet of info._difficultyBeatmapSets) {
    for (let beatmap of beatmapSet._difficultyBeatmaps) {
      const f = await requireEntry(beatmap._beatmapFilename);
      if (f) {
        try {
          const content = JSON.parse(await f.async('text'));
          if (content._notes.length < 100) {
            return res
                .status(400)
                .send('At least 100 notes are required. This is saber.ninja not saber.lazy!')
                .end();
          }
        } catch (error) {
          return res.status(400).send(`Invalid format in ${beatmap._beatmapFilename}`).end();
        }
      }
    }
  }
  if (missingEntries.length > 0) {
    return res.status(400).send(`Missing bundle entries: ${missingEntries.join(', ')}`).end();
  }

  const id = crypto.randomBytes(6).toString('hex')
  const level = {
      id: id,
      uploader: 'fcfs',
      owner: req.cookies.auth,
      bundle: upload.data,
      name: upload.name.split('.')[0],
      song: info._songName,
      artist: info._songAuthorName,
      songFilename: info._songFilename,
      coverFilename: (hasCoverImage? info._coverImageFilename:''),
      beatmapFilename: info._difficultyBeatmapSets[0]._difficultyBeatmaps[0]._beatmapFilename,
      beatsPerMinute: info._beatsPerMinute,
      playTested: false,
  };
  try {
    await upsertLevel(level);
    res.redirect(302, '/');
  } catch (error) {
    next(error);
  }
});

app.post('/level/:id/markplaytested', async (req, res, next) => {
  try {
    const level = await loadLevel(req.params.id);
    if (!level || req.cookies.auth != CLIENT_AUTH_COOKIE) {
      return res.status(400).send('Only admins can confirm play-testing.').end();
    }

    level.playTested = true;
    await upsertLevel(level);
    res.status(200).send('Play-testing complete.').end();
  } catch (error) {
    next(error);
  }
})

const hasLevelAccess = (req, level, requirePlayTest=false) => {
  const isPublic = requirePlayTest ? level.playTested : true;
  return req.cookies.auth == level.owner
      || req.cookies.auth == CLIENT_AUTH_COOKIE
      || isPublic;
};

app.get('/level/:id/bundle', async (req, res, next) => {
  try {
    const level = await loadLevel(req.params.id);
    if (!level || !hasLevelAccess(req, level)) {
      return res.status(404).send("Level doesn't exist or hasn't been play-tested.").end();
    }
    res
        .status(200)
        .header('Content-Type', 'application/octet-stream')
        .header('Content-Disposition', `attachment; filename="${level.name}.zip"`)
        .send(level.bundle)
        .end();
  } catch (error) {
    next(error);
  }
});

app.get('/level/:id/beatmap', async (req, res, next) => {
  try {
    const level = await loadLevel(req.params.id);
    if (!level || !hasLevelAccess(req, level)) {
      return res.status(404).send("Level doesn't exist or hasn't been play-tested.").end();
    }
    const zip = await jsZip.loadAsync(level.bundle);
    const beatmap = await zip.file(level.beatmapFilename).async('text');
    res
        .status(200)
        .header('Content-Type', 'application/json')
        .send(beatmap)
        .end();
  } catch (error) {
    next(error);
  }
});

app.get('/level/:id/cover', async (req, res, next) => {
  try {
    const level = await loadLevel(req.params.id);
    if (!level || !hasLevelAccess(req, level)) {
      return res.status(404).send("Level doesn't exist or hasn't been play-tested.").end();
    }
    if(!level.coverFilename) {
      return res.status(404).send("Level does not have a cover photo.").end();
    }
    const mime = imageFilenameToMime(level.coverFilename);
    if (!mime) {
      // This should be validated on upload.
      return res.status(500).send('An internal error occurred.').end();
    }
    const zip = await jsZip.loadAsync(level.bundle);
    const cover = await zip.file(level.coverFilename).async('nodebuffer');
    res
        .status(200)
        .header('Content-Type', mime)
        .send(cover)
        .end();
  } catch (error) {
    next(error);
  }
});

app.get('/level/:id/song', async (req, res, next) => {
  try {
    const level = await loadLevel(req.params.id);
    if (!level || !hasLevelAccess(req, level)) {
      res.status(404).send("Level doesn't exist or hasn't been play-tested.").end();
    }
    const mime = audioFilenameToMime(level.songFilename);
    if (!mime) {
      // This should be validated on upload.
      return res.status(500).send('An internal error occurred.').end();
    }
    const zip = await jsZip.loadAsync(level.bundle);
    const song = await zip.file(level.songFilename).async('nodebuffer');
    res
        .status(200)
        .header('Content-Type', mime)
        .send(song)
        .end();
  } catch (error) {
    next(error);
  }
});

const sanitizeLevel = (level) => {
  return {
      id: level.id,
      name: level.name,
      song: level.song,
      artist: level.artist,
      uploader: level.uploader,
      beatsPerMinute: level.beatsPerMinute,
  };
};

const escapeForHtml = (text) => {
  return text.replace(/</g, '&lt;').replace(/>/g, '&gt;');
};

const mainPageHandler = async (req, res, next) => {
  try {
    const needsSignup = !req.cookies.auth;
    let levels = [];
    let preview = null;
    let banner = null;
    if (!needsSignup) {
      const rawLevels = await loadOwnedLevels(req.cookies.auth);
      levels = rawLevels.map((level) => sanitizeLevel(level));
      if (req.params.id) {
        const previewLevel = await loadLevel(req.params.id);
        if (hasLevelAccess(req, previewLevel, /* requirePlaytest= */ true)) {
          preview = sanitizeLevel(previewLevel);
        } else {
          banner = 'That level isn\'t play-tested yet!';
        }
      }
    }
    const html = `<!DOCTYPE html>
      <html>
        <head>
          <title>Saber.ninja</title>
          <script src="/app.js" async defer></script>
          <link rel="stylesheet" href="/app.css">
        </head>
        <body data-needs-signup="${needsSignup}">
          ${preview ? `<div id="preview-metadata" class="hidden">${escapeForHtml(JSON.stringify(preview))}</div>` : ''}
          <div id="upload-metadata" class="hidden">${escapeForHtml(JSON.stringify(levels))}</div>
          <div class="header">
            Saber.<span class="ninja">ninja</span>
          </div>
          <div class="warning">${banner ? banner : 'Ensure chrome://flags/#enable-gpu-rasterization is enabled for browser preview to work'}</div>
          <div id="page" class="content"></div>
        </body>
      </html>`
    res.status(200).header('Content-Type', 'text/html').send(html).end();
  } catch (error) {
    next(error);
  }
};

app.get('/', mainPageHandler);
app.get('/preview/:id', mainPageHandler);

app.post('/signup', (req, res, next) => {
  res
      .cookie('auth', urlBase64.encode(crypto.randomBytes(16)), {httpOnly: true})
      .redirect(302, '/');
});

app.post('/chat', async (req, res, next) => {
  try {
    const msg = req.body.message;
    let response = null;
    if (isLinkRegex.test(msg)){
      if(isSaberRegex.test(msg)) {
        const [_, __, id] = msg.match(isSaberRegex);
        const level = await loadLevel(id);
        if (level && level.playTested) {
          console.log('Accepted submission: ' + msg);
          response = neatResponse;
          await pubsub.topic('xss-bsaber').publish(Buffer.from(JSON.stringify({
            url: msg,
            service: 'bsaber',
          })));
        } else {
          console.log('Rejected submission (not playtested): ' + msg);
          response = {
            message: notPlayTestedResponse.message.replace("{id}", id),
          };
        }
      } else {
        console.log('Rejected submission (not bsaber preview link): ' + msg);
        response = invalidLinkResponse;
      }
    } else {
      console.log('Rejected submission (not a link): ' + msg);
      response = sgtPepperTaunt;
    }
    res
      .status(200)
      .header('Content-Type', 'application/json')
      .send(JSON.stringify(response))
      .end();
  } catch (error){
    next(error);
  }
});

const PORT = process.env.PORT || 8080;
app.listen(process.env.PORT || 8080, () => {
  console.log(`App listening on port ${PORT}`);
  console.log('Press Ctrl+C to quit.');
});

module.exports = app;
