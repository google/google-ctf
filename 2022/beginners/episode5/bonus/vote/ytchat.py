#!/usr/bin/env python3
# Copyright 2022 Google LLC
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
import os
import sys
import json
import datetime
import dateutil.tz
import time

import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
import googleapiclient.errors

API_SCOPES = [
    "https://www.googleapis.com/auth/youtube",
    "https://www.googleapis.com/auth/youtube.force-ssl",
    "https://www.googleapis.com/auth/youtube.readonly"
]

CLIENT_SECRETS_FILE = "client_secret.json"
OAUTH_CREDS_FILE = "oauth_credentials.json"
PAGE_TOKEN_FILE = "page_tokens.json"
LAST_MESSAGE_FILE = "last_message.json"

class YouTubeChatRetry:
  def __init__(self, messages=None):
    self.messages = messages

class YouTubeChat:
  def __init__(self):
    self.last_message = 0  # Timestamp in YT API server time.
    self.last_message_load()

    self.last_request = 0
    self.default_delay = 5.0
    self.delay = self.default_delay

    self.page_tokens = {}
    self.page_tokens_load()

    self.start_time = time.time()
    self.api_counter = 0

    # If set, messages without this prefix are ignored.
    self.filter_prefix = "!"

    self.livechat_id = None
    self.prepare_api()

  def prepare_api(self):
    # Disable OAuthlib's HTTPS verification when running locally.
    # *DO NOT* leave this option enabled in production.
    #os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

    api_service_name = "youtube"
    api_version = "v3"

    # Get credentials and create an API client
    flow = google_auth_oauthlib.flow.InstalledAppFlow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, API_SCOPES
    )

    credentials = None
    try:
      credentials = (
          google.oauth2.credentials.Credentials.from_authorized_user_file(
              OAUTH_CREDS_FILE
          )
      )
    except ValueError as e:
      print("warning:", e)
    except FileNotFoundError as e:
      print("warning:", e)

    if credentials is None:
      credentials = flow.run_console()

      with open(OAUTH_CREDS_FILE, "w") as f:
        f.write(credentials.to_json())
    else:
      print("note: using creds from file")

    self.youtube = googleapiclient.discovery.build(
        api_service_name, api_version, credentials=credentials
    )

    self.refresh_livechat_id()

  def last_message_load(self):
    try:
      with open(LAST_MESSAGE_FILE) as f:
        self.last_message = json.load(f)["timestamp"]
    except FileNotFoundError:
      return
    except json.decoder.JSONDecodeError:
      return

  def last_message_save(self):
    with open(LAST_MESSAGE_FILE, "w") as f:
      json.dump({
          "timestamp": self.last_message
      }, f)

  def page_tokens_save(self):
    with open(PAGE_TOKEN_FILE, "w") as f:
      json.dump(self.page_tokens, f)

  def page_tokens_load(self):
    try:
      with open(PAGE_TOKEN_FILE) as f:
        self.page_tokens = json.load(f)
    except FileNotFoundError:
      return
    except json.decoder.JSONDecodeError:
      return

  def page_token_add(self, livechat_id, page_token):
    self.page_tokens[livechat_id] = page_token
    self.page_tokens_save()

  def page_token_del(self, livechat_id):
    try:
      del self.page_tokens[livechat_id]
    except KeyError:
      return
    self.page_tokens_save()

  def page_token_get(self, livechat_id):
    return self.page_tokens.get(livechat_id)

  def execute_request(self, request):
    while True:
      now = time.time()
      if now < self.last_request + self.delay:
        time.sleep(0.3)
        continue
      break

    self.last_request = now
    self.api_counter += 1
    return request.execute()

  def get_api_stats(self):
    time_from_start = (time.time() - self.start_time)
    if time_from_start < 1.0:
      time_from_start = 1.0

    calls_count = self.api_counter
    calls_per_sec = calls_count / time_from_start
    calls_per_day = int(calls_per_sec * 86400 + 0.99999)
    return {
      "calls_count": calls_count,
      "calls_per_sec": calls_per_sec,
      "calls_per_day": calls_per_day
    }

  def get_newest_livechat_id(self):
    request = self.youtube.liveBroadcasts().list(
        part="snippet,contentDetails,status",
        broadcastType="all",
        broadcastStatus="active"
    )
    response = self.execute_request(request)

    # This returns the NEWEST live event. And only one.
    live_info = None
    live_start_time = 0
    for item in response["items"]:
      status = item["status"]["lifeCycleStatus"]
      if status != "live":
        continue

      start_time = self.to_timestamp(item["snippet"]["actualStartTime"])
      livechat_id = item["snippet"]["liveChatId"]

      if start_time > live_start_time:
        live_start_time = start_time
        live_info = (livechat_id, item)

    return live_info

  def refresh_livechat_id(self):
    print("note: refreshing livechat id... ", end="")
    live_info = self.get_newest_livechat_id()
    if live_info is None:
      self.livechat_id = None
      print("failed (likely no livestream)")
      return False

    livechat_id = live_info[0]

    if livechat_id != self.livechat_id:
      self.livechat_id = livechat_id
      print("successful (new id)")
    else:
      print("successful (no change)")

    return True

  def get_new_messages_worker(self):
    if self.livechat_id is None:
      if not self.refresh_livechat_id():
        print("error: couldn't get messages, no livestream")
        return None

    page_token = self.page_token_get(self.livechat_id)
    if page_token is None:
      request = self.youtube.liveChatMessages().list(
          liveChatId=self.livechat_id,
          part="id,snippet",
          maxResults=2000
      )
    else:
      request = self.youtube.liveChatMessages().list(
          liveChatId=self.livechat_id,
          part="id,snippet",
          maxResults=2000,
          pageToken=page_token
      )

    try:
      response = self.execute_request(request)
    except googleapiclient.errors.HttpError as e:
      if e.error_details[0]["reason"] == 'pageTokenInvalid':
        print("error: invalid page token (purging)")
        self.page_token_del(self.livechat_id)
        return YouTubeChatRetry()
      else:
        print("error:", e.error_details)
      return None

    # Recalculate delay before next request.
    delay = float(response["pollingIntervalMillis"]) / 1000.0
    self.delay = max(delay, self.default_delay)

    next_page_token = response["nextPageToken"]
    self.page_token_add(self.livechat_id, next_page_token)

    offline = False
    if "offlineAt" in response:
      offline = True
      print("warning: stream went offline (1)")

    messages = []
    for msg in response["items"]:
      snippet = msg["snippet"]
      msg_type = snippet["type"]

      if msg_type == "chatEndedEvent":
        offline = True
        print("warning: stream went offline (2)")
        continue

      if msg_type != "textMessageEvent":
        continue

      text = snippet["textMessageDetails"]["messageText"]
      author = snippet["authorChannelId"]
      timestamp = self.to_timestamp_ext(snippet["publishedAt"])

      if self.filter_prefix and not text.startswith(self.filter_prefix):
        continue

      if timestamp < self.last_message:
        continue

      # Assumption: messages are sorted oldest-to-newest. If this assumption
      # is broken, the next line needs to be brought outside of the loop.
      self.last_message = timestamp

      messages.append({
          "text": text,
          "author": author,
          "timestamp": timestamp
      })

    self.last_message_save()

    if offline:
      self.page_token_del(self.livechat_id)
      self.livechat_id = None

    if (response["pageInfo"]["totalResults"] !=
        response["pageInfo"]["resultsPerPage"]):
      return YouTubeChatRetry(messages)

    return messages

  # This method is blocking and might take a while!
  def get_new_messages(self):
    messages = []
    while True:
      res = self.get_new_messages_worker()

      if res is None:
        return messages if messages else None

      if type(res) is YouTubeChatRetry:
        if res.messages:
          messages.extend(res.messages)
        continue

      messages.extend(res)
      return messages

  def to_timestamp(self, s):
    s = s[:-1] + ".000000+00:00"
    return self.to_timestamp_ext(s)

  def to_timestamp_ext(self, s):
    # Example: 2022-09-29T14:50:21.232442+00:00
    s = "%s:%s:%s%s" % tuple(s.split(":"))
    d = datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%f%z")
    d = d.astimezone(dateutil.tz.tzlocal())
    timestamp = time.mktime(d.timetuple())
    return timestamp

def main():
  yt = YouTubeChat()

  while True:
    messages = yt.get_new_messages()
    if messages is None:
      continue

    print("---")
    for msg in messages:
      print(json.dumps(msg, indent=2))

if __name__ == "__main__":
  main()
