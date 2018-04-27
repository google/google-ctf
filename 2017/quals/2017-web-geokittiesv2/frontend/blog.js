// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.



const datastore = require('@google-cloud/datastore')();
const htmlparser = require('htmlparser2');
const uuidV4 = require('uuid/v4');
const http = require('http');

const KIND = 'Comment';
const allowedTags = ['p', 'a', 'b', 'img', 'br', 'i'];
const allowedTypes = ['tag', 'text']

function insert_comment(content) {
    var id = uuidV4();
    var key = datastore.key([KIND, id]);

    return datastore.save({
        key: key,
        data: { content: content, viewed: false },
    }).then(() => {
        return id;
    });
}

function get_comment(id) {
    var key = datastore.key([KIND, id]);
    return datastore.get(key).then((result) => {
        if (!result[0])
            throw new Exception();
        return result[0];
    });
}

function delete_comment(id) {
    var key = datastore.key([KIND, id]);
    return datastore.delete(key);
}

function set_comment_viewed(id) {
    var key = datastore.key([KIND, id]);
    return datastore.get(key).then((result) => {
        if (!result[0])
            return;

        var comment = result[0];
        comment.viewed = true;
        return datastore.save({
          key: key,
          data: comment
        });
    });
}

function check_comment(comment) {
    function validate(node)
    {
        if (allowedTypes.indexOf(node.type) == -1)
            throw 'Invalid type';
        else if (node.type == 'tag' && allowedTags.indexOf(node.name) === -1)
            throw 'Invalid tag';

        for (var name in node.attribs) {
            var value = node.attribs[name];

            if (/^on.+/.test(name) && value !== '')
                throw 'Invalid event';
            console.log(value)
            if (name == 'href' && /^(https?:)/.test(value) === false)
                throw 'Invalid link';
        }

        for (var i in node.children) {
            validate(node.children[i]);
        }
    }

    var handler = new htmlparser.DomHandler(function (error, dom) {
        if (error) {
            throw error;
        } else {
            for (var i in dom)
                validate(dom[i]);
        }
    });

    try {
        var parser = new htmlparser.Parser(handler);
        parser.write(comment);
        parser.end();
    } catch (err) {
        console.log(err);
        return false;
    }

    return true;
}


module.exports = {
    check_comment: check_comment,
    insert_comment: insert_comment,
    get_comment: get_comment,
    delete_comment: delete_comment,
    set_comment_viewed: set_comment_viewed
}
