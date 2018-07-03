// Copyright 2017, Google, Inc.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

'use strict';

const express = require('express');
const bodyParser = require('body-parser');
const images = require('../lib/images');
const auth = require('../lib/auth');

function getModel () {
  return require(`./model-${require('../config').get('DATA_BACKEND')}`);
}

const router = express.Router();

router.use(auth.router);
router.use(auth.template);

// Automatically parse request body as form data
router.use(bodyParser.urlencoded({ extended: false }));

// Set Content-Type for all responses for these routes
router.use((req, res, next) => {
  res.set('Content-Type', 'text/html');
  next();
});

/**
 * GET /books
 *
 * Display a page of books (up to ten at a time).
 */
router.get('/', (req, res, next) => {
  res.render('books/main.pug', {});
});

/**
 * GET /books/add
 *
 * Display a form for creating a book.
 */
router.get('/add', auth.required, (req, res) => {
  res.render('books/form.pug', {
    book: {},
    action: 'Add'
  });
});

/**
 * POST /books/add
 *
 * Create a book.
 */
// [START add]
router.post(
  '/add',
  auth.required,
  images.multer.single('image'),
  images.sendUploadToGCS,
  (req, res, next) => {
    let data = req.body;

    if (req.user.name == 'admin')
      throw 'Stahp';

    // If the user is logged in, set them as the creator of the book.
    if (req.user) {
      data.createdBy = req.user.name;
      data.createdById = req.user.id;
    } else {
      data.createdBy = 'Anonymous';
    }

    // Was an image uploaded? If so, we'll use its public URL
    // in cloud storage.
    if (req.file && req.file.cloudStoragePublicUrl) {
      data.imageUrl = req.file.cloudStoragePublicUrl;
    }

    // Save the data to the database.
    getModel().create(data, (err, savedData) => {
      if (err) {
        next(err);
        return;
      }
      res.redirect(`${req.baseUrl}/${savedData.id}`);
    });
  }
);
// [END add]


// [START mine]
// Use the auth.required middleware to ensure that only logged-in users
// can access this handler.
router.get('/mine', auth.required, (req, res, next) => {
  getModel().listBy(
    req.user.id,
    10,
    req.query.pageToken,
    (err, entities, cursor, apiResponse) => {
      if (err) {
        next(err);
        return;
      }
      res.render('books/list.pug', {
        books: entities,
        nextPageToken: cursor
      });
    }
  );
});
// [END mine]

/**
 * GET /books/:id/edit
 *
 * Display a book for editing.
 */
router.get('/:book/edit', auth.required, (req, res, next) => {
  getModel().read(req.params.book, (err, entity) => {
    if (err) {
      next(err);
      return;
    }
    res.render('books/form.pug', {
      book: entity,
      action: 'Edit'
    });
  });
});

/**
 * POST /books/:id/edit
 *
 * Update a book.
 */
router.post(
  '/:book/edit',
  auth.required,
  images.multer.single('image'),
  images.sendUploadToGCS,
  (req, res, next) => {

    if (req.params.book == '5eab1600-b86e-4ebc-af0f-7d9f618c41c3')
      throw 'Stahp';

    let data = req.body;

    // Was an image uploaded? If so, we'll use its public URL
    // in cloud storage.
    if (req.file && req.file.cloudStoragePublicUrl) {
      req.body.imageUrl = req.file.cloudStoragePublicUrl;
    }

    getModel().update(req.params.book, data, (err, savedData) => {
      if (err) {
        next(err);
        return;
      }
      res.redirect(`${req.baseUrl}/${savedData.id}`);
    });
  }
);

/**
 * GET /books/:id
 *
 * Display a book.
 */
router.get('/:book', (req, res, next) => {
  getModel().read(req.params.book, (err, entity) => {
    if (err) {
      next(err);
      return;
    }
    res.render('books/view.pug', {
      book: entity
    });
  });
});

/**
 * GET /books/:id/delete
 *
 * Delete a book.
 */
router.get('/:book/delete', auth.required, (req, res, next) => {
  if (req.params.book == '5eab1600-b86e-4ebc-af0f-7d9f618c41c3')
    throw 'Stahp';

  getModel().delete(req.params.book, (err) => {
    if (err) {
      next(err);
      return;
    }
    res.redirect(req.baseUrl);
  });
});

/**
 * Errors on "/books/*" routes.
 */
router.use((err, req, res, next) => {
  // Format error and forward to generic error handler for logging and
  // responding to the request
  err.response = err.message;
  next(err);
});

module.exports = router;
