#!/usr/bin/python
#
# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Main application."""

import base64
import hashlib
import hmac
import logging
import os
import textwrap
import time
import urllib
import webapp2

from google.appengine.api import datastore_errors
from google.appengine.api import memcache
from google.appengine.ext import ndb

HANDICAP = 10 * 2

FLAG_LENGTH = 64

BAN = 30 * 60 / HANDICAP


class QUOTAS(object):
  HITS = 13
  ERRS = 2


class WINDOWS(object):
  HITS = 10 * 60 / HANDICAP
  ERRS = 10 * 60 / HANDICAP
  MAX = FLAG_LENGTH * (5 + 10 * 60 / HANDICAP)


class QuotaModel(ndb.Model):
  start = ndb.FloatProperty()
  banned = ndb.FloatProperty()
  hits = ndb.FloatProperty(repeated=True)
  errs = ndb.FloatProperty(repeated=True)


class UserModel(ndb.Model):
  user = ndb.StringProperty()
  password = ndb.StringProperty()


class Key(ndb.Model):
  secret = ndb.StringProperty()


class Login(webapp2.RequestHandler):
  """Login servlet with abuse detection signals."""
  key = Key.get_or_insert("key", namespace="default").secret.encode("utf-8")

  def PrintQuotaError(self):
    self.response.write(
        textwrap.dedent("""
      <h1>Abuse detection system triggered!</h1>
      <h3>You have been banned for %s seconds.</h3>
      <p>
        <b>
          If you believe this is a mistake, contact your system administrator.
        </b>
        Possible reasons include:
        <ul>
          <li>Generating too many errors too quickly
            <!--DEBUG: %s queries / %s seconds--></li>
          <li>Making too many requests too quickly
            <!--DEBUG: %s queries / %s seconds--></li>
          <li>Spending too much time without authenticating
            <!--DEBUG: %s seconds--></li>
        </ul>
      </p>
    """) % (BAN, QUOTAS.ERRS, WINDOWS.ERRS, QUOTAS.HITS, WINDOWS.HITS,
            WINDOWS.MAX))
    self.response.set_status(400)

  @ndb.transactional
  def dispatch(self):
    try:
      hostname = self.request.host.split("-")[0]
      ban = memcache.get("ban:%s" % hostname)
      if ban and ban > time.time():
        return self.PrintQuotaError()
      flag = "CTF{%s-%s}" % (
          hostname, base64.b64encode(hmac.new(
              self.key, hostname, hashlib.sha512
          ).digest()[:(6*FLAG_LENGTH/8)], "-_"))
      self.quota = QuotaModel.get_or_insert(hostname, start=time.time())
      self.user = UserModel.get_or_insert(
          "user", parent=self.quota.key, user="admin", password=flag)
      time_limit = self.quota.start + WINDOWS.MAX
      if self.quota.banned > time.time() or time_limit < time.time():
        return self.PrintQuotaError()
      hit_window = time.time() - WINDOWS.HITS
      self.quota.hits = [hit for hit in self.quota.hits if hit > hit_window]
      err_window = time.time() - WINDOWS.ERRS
      self.quota.errs = [err for err in self.quota.errs if err > err_window]
    except Exception as e:  # pylint: disable=broad-except
      logging.exception("Dispatch error: %s", e)
      self.abort(500)
    try:
      self.quota.hits.append(time.time())
      super(Login, self).dispatch()
    except datastore_errors.TransactionFailedError:
      raise
    except Exception as e:  # pylint: disable=broad-except
      self.quota.errs.append(time.time())
      logging.exception("Handler error: %s", e)
      self.redirect("/index.html?e=%s" % urllib.quote(str(e)))
    finally:
      if (len(self.quota.hits) > QUOTAS.HITS or
          len(self.quota.errs) > QUOTAS.ERRS):
        self.quota.banned = time.time() + BAN
        memcache.add(key="ban:%s" % hostname, value=self.quota.banned, time=BAN)
      self.quota.put()

  def post(self):
    sql = "SELECT password FROM UserModel WHERE ANCESTOR IS :1 AND user = '%s'"
    query = ndb.gql(sql % self.request.get("user"), self.quota.key)
    result = query.fetch(1)
    if not result:
      self.redirect("/index.html?e=%s" % urllib.quote("Wrong username"))
    elif result[0].password != self.request.get("password"):
      raise Exception("Wrong password")
    else:
      self.response.write(self.request.get("password"))

  def get(self):
    if self.request.host.startswith("qu0t45"):
      self.redirect("/")
    else:
      self.redirect("//qu0t45%swww-%s/login" %
                    (base64.b64encode(os.urandom(6 * 16 / 8), "__"),
                     "abuse.web.ctfcompetition.com"))


app = webapp2.WSGIApplication(
    [
        ("/login", Login),
    ], debug=False)
