# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Backend parsing."""
# coding: utf8
import json
import os
import logging
from flask import Flask
from flask import render_template
from flask import request
from flask import Response
from flask_sqlalchemy import SQLAlchemy
from lxml import etree as ET
from sqlalchemy import exc
from StringIO import StringIO

# Creation of the flask application.
app = Flask(__name__)

# Creation of the SQL engine.
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
db = SQLAlchemy(app)


def decode_blind(sourcebraille):
  """Braille decoder."""
  blind = {
      '1': 'a',
      '12': 'b',
      '14': 'c',
      '145': 'd',
      '15': 'e',
      '124': 'f',
      '1245': 'g',
      '125': 'h',
      '24': 'i',
      '245': 'j',
      '13': 'k',
      '123': 'l',
      '134': 'm',
      '1345': 'n',
      '135': 'o',
      '1234': 'p',
      '12345': 'q',
      '1235': 'r',
      '234': 's',
      '2345': 't',
      '136': 'u',
      '1236': 'v',
      '2456': 'w',
      '1346': 'x',
      '13456': 'y',
      '1356': 'z',
      '': ' '
  }
  # decode input.
  arr = sourcebraille.split('0', 50)
  output = ''
  for x in arr:
    if str(x) != '' and str(x) in blind:
      output += blind[str(x)]
  # if not encoded properly - return no result.
  if not output:
       output = 'NR'
  return output


def get_data(input1):
  """Get data."""
  sql = 'SELECT information1 AS ValueSearch FROM blindtable WHERE city=:city'
  try:
      resulteval = db.session.execute(sql, {'city': input1}).fetchone()
      if resulteval is None:
          result = 'No result found'
      else:
          result = resulteval[0]
  except exc.SQLAlchemyError:
      logging.exception('sql')
      result = 'No result found'
  return result


def create_file(fileinput, content):
  """Create file if not exists."""
  try:
    with open(fileinput, 'w') as f:
      f.write(content)
      f.close()
      f = open(fileinput, 'r')
      f.close()
  except:
    logging.exception('failed to create file')


def setup():
  # Create flag file.
  flag = os.environ.get('GCTF_FLAG') or 'CONTACT_ADMIN'
  create_file('/flag', flag)
  # Populate db
  db.engine.raw_connection().executescript(open('data.sql').read())

setup()


########################################################
# Controllers
########################################################


@app.route('/')
def index():
  """Homepage controller."""
  return render_template('index.html')


@app.route('/api/search', methods=['POST'])
def api():
  """Controller for Ajax interaction."""
  # Collect posted data.
  posted_data = request.data
  # Collect posted data type.
  posted_type = request.content_type
  processed_data, result, whatformat = None, None, None

  if posted_type == 'application/json':
    # Verify if it is JSON.
    try:
        whatformat = "json"
        processed_data = json.loads(posted_data)
    except ValueError as e:
        result = {'ValueSearch': e.message}
  # Verify if it is XML.
  elif posted_type == 'application/xml' or posted_type == 'text/xml':
    try:
        # Configure the parser to be vulnerable.
        whatformat = "xml"
        parser = ET.XMLParser(
            dtd_validation=True, load_dtd=True, no_network=True, huge_tree=True)
        tree = ET.parse(StringIO(posted_data), parser)
        elem = tree.getroot()
        processed_data = elem.text
    except ET.ParseError as e:
        # Display error message.
        result = e.message
   # If not JSON or XML.
  else:
    result = {'ValueSearch': 'invalid format'}

  # Return value and mime type based on the format.
  if whatformat == "json":
    if not result:
        result = {'ValueSearch': get_data(decode_blind(processed_data['message']))}
    return Response(json.dumps(result), mimetype='application/json; charset=utf-8')
  elif whatformat == "xml":
    if not result:
        result = get_data(decode_blind(processed_data))
    return Response(result, mimetype='text/xml')
  else:
    return Response(json.dumps(result), mimetype='application/json; charset=utf-8')


########################################################
# Boilerplate for testing app locally
########################################################

if __name__ == '__main__':
  app.run(debug=False)
