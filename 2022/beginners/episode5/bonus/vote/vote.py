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
import datetime
import hashlib
import json
import os
import queue
import random
import socket
import sys
import threading
import time

script_dir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(f"{script_dir}/../py_common")
import textbuffer
import ytchat
from voting_config import *
from filters import badlang_filter_load, badlang_filter_check

W = textbuffer.TextBuffer.W
H = textbuffer.TextBuffer.H
txt = None

BASIC_UDP_PORT = 23410
basic_socket = None

# Lag between action in Python and action being observable on YT by viewers.
LAG = 3.5

# Note: Both CMD_VOTE_DURATION and VOTE_VOTE_DURATION values represent only a
# part of voting time. Actual votes are longer to compensate for latency, as
# well as some other stuff.
CMD_VOTE_DURATION = 15  # Seconds.
CMD_BOT_DELAY = 7  # Seconds (how frequently to call the API).
CMD_PRESENTATION_DURATION = 10  # Seconds.
VOTE_BOT_DELAY = 5  # Seconds (how frequently to call the API).
VOTE_VOTE_DURATION = 10  # Seconds.
STOP_BOT_DELAY = 0  # This is subject to ytchat-side delay anyway.
PHASE_FAIL_DELAY = 60  # When there were not enough votes or cmds.

if FAST_API_ACCESS:
  CMD_BOT_DELAY = 1.5
  VOTE_BOT_DELAY = 1.2

CMD_LENGTH_LIMIT = 71

VOTE_REQUIREMENT_START = 10
VOTE_REQUIREMENT_MIN = 10
VOTE_REQUIREMENT_MAX = 100
VOTE_REQUIREMENT_STEP_DOWN = 10
VOTE_REQUIREMENT_STEP_UP = 1

if VOTE_DEBUG_MODE:
  print("note: \x1b[31mVOTE_DEBUG_MODE\x1b[m mode!")
  VOTE_REQUIREMENT_START = 1
  VOTE_REQUIREMENT_MIN = 1
  VOTE_REQUIREMENT_MAX = 1
  VOTE_REQUIREMENT_STEP_DOWN = 0
  VOTE_REQUIREMENT_STEP_UP = 0

GRACE_PERIOD = 5.0  # How old votes / cmds to still respect.

BAN_LIST_FILE = "ban_list.json"

def send_to_basic(line):
  basic_socket.sendto(line.encode(), ("127.0.0.1", BASIC_UDP_PORT))

# TODO: And likely we also need a way to reset the program.
# TODO: Add an interface for manual administration:
#       - switching to fully-moderated mode (accept/reject last 4 cmds)
#       - being able to un-ban people by their YT id
class VotingBot:
  def __init__(self):
    self.queue = None
    self.ready = threading.Event()
    self.state = None
    self.next_state = None
    self.vote_start = None
    self.yt = None

    self.ban_list = {}
    self.ban_list_load()

    self.delay = 5.0  # Delay between API calls.

    self.th = threading.Thread(target=self.worker, daemon=True)
    self.th.start()

  def is_ready(self):
    return self.ready.is_set()

  def set_delay(self, delay):
    # Note: delay is still subject to yt.default_delay.
    self.delay = delay

  def start_vote(self, cmd):
    self.queue = queue.Queue()
    self.next_state = cmd
    self.vote_start = time.time()
    self.voter_list = set()

  def stop_vote(self):
    self.next_state = None

  def ban(self, id_hash, text):
    print(f"note: banning {id_hash} for '{text}'")
    self.ban_list[id_hash] = text

    self.ban_list_save()

  def ban_list_load(self):
    try:
      with open(BAN_LIST_FILE) as f:
        self.ban_list = json.load(f)
    except FileNotFoundError:
      return
    except json.decoder.JSONDecodeError:
      return

  def ban_list_save(self):
    with open(BAN_LIST_FILE, "w") as f:
      json.dump(self.ban_list, f)

  def maybe_fetch_votes(self, force=False):
    now = time.time()
    if not force and now < self.last_fetch + self.delay:
      return  # Do nothing.

    res = self.yt.get_new_messages()
    self.last_fetch = time.time()

    if res is None:
      print("note: couldn't get votes - YT video offline?")
      return

    prefix = f"{self.state} "

    for msg in res:
      timestamp = msg["timestamp"]
      text = msg["text"]
      author = msg["author"]

      # This is comparing YT server time with our server time, however it seems
      # there is basically no time skew. But... this is a bit fragile.
      if timestamp < self.vote_start - GRACE_PERIOD:
        print(f"debug: ignoring too old message '{text}'")
        continue

      if not text.startswith(prefix):
        continue

      if author in self.voter_list and not VOTE_DEBUG_MODE:
        print(f"debug: ignoring double-vote '{text}'")
        continue
      self.voter_list.add(author)

      text = text.strip()
      text_ascii_pass = True
      for ch in text:
        ch = ord(ch)
        if ch < 0x20 or ch >= 0x7f:
          text_ascii_pass = False
          break

      if not text_ascii_pass:
        print(f"note: rejected (ascii): '{text}'")
        continue

      # TODO: add a really basic syntax check maybe?

      id_hash = hashlib.md5(author.encode()).hexdigest()
      if id_hash in self.ban_list:
        print(f"note: ignoring message from banned person: '{text}'")
        continue

      if not badlang_filter_check(text):
        print(f"note: bad lang detected, banning: '{text}'")
        self.ban(id_hash, text)
        continue

      self.queue.put(text)

  def worker(self):
    print("note: readying YT voting bot...")

    last_state = None
    yt = ytchat.YouTubeChat()
    self.yt = yt

    if FAST_API_ACCESS:
      yt.default_delay = 1.1
    else:
      yt.default_delay = 2.0

    # Roll chat forward until most recent messages are present. This might be
    # long if there are a lot of messages on the chat and the bot just joined.
    res = yt.get_new_messages()

    if res is None:
      print("note: voting bot ready (but stream likely not?)")
    else:
      print(f"note: voting bot ready (discarded {len(res)} old messages)")

    self.ready.set()

    self.last_fetch = time.time()
    while True:
      # State is changing.
      if self.next_state != self.state:
        if self.state is None and self.next_state:
          # Starting gathering votes (timestamp should be at self.vote_state).
          self.state = self.next_state
          continue
        else:
          # Do last data pull.
          self.maybe_fetch_votes(force=True)
          self.state = self.next_state
          continue

      # State is stable.
      if self.state is None:
        time.sleep(0.1)
        continue

      self.maybe_fetch_votes()
      time.sleep(0.1)

def banner():
  txt.set_attr(True)
  txt.printxy(W - 13, H - 1, "\x0b VOTING BOT")
  txt.putchar_xy(W - 1, H - 1, " ")
  txt.set_attr(False)

def section_name(y, s):
  txt.fill_line(y, '\x10')
  txt.print_center(y, f"\x19 {s} \x1a")

class SceneStarting:
  def setup(self):
    txt.set_attr(False)
    txt.clear()
    banner()

    txt.print_center(H//2 - 1, "Initializing voting bot   ")
    self.i = 0

  def anim(self):
    self.i += 1
    if self.i == 4:
      self.i = 0
    i = self.i
    j = 3 - i
    txt.print_center(H//2 - 1, "Initializing voting bot" + ("." * i) + (" " * j))

class SceneVoting:
  def __init__(self):
    self.anim_duration = 3.0  # Set this +- to how frequently votes are received
                              # from the yt bot.
    self.command_shown_duration = 2.0  # How long is a command shown.

    self.end_time = 0
    self.last_time = None

    self.last_time_shown = 0

  def setup(self):
    txt.set_attr(False)
    txt.clear()
    banner()

  def setup_phase_cmd(self, duration):
    self.setup()

    txt.printxy(1, 0, "Phase: Voters propose commands")
    txt.printxy(1, 1, " Chat: !cmd command")
    txt.printxy(1, 2, f" Time: {duration} sec [starting soon]")

    section_name(4, "Proposed commands")

    section_name(7, "More info")
    txt.printxy(0, 8, "At least 1 command needs to be pro-")
    txt.printxy(0, 9, "posed. If there are more than 4 com-")
    txt.printxy(0, 10, "mands proposed, 4 will be chosen at")
    txt.printxy(0, 11, "random for the next phase. Length")
    txt.printxy(0, 12, "limit of a command is 71 characters.")

  def setup_phase_cmd_failed(self):
    txt.clear_line(0)
    txt.printxy(1, 0, "Phase: Cooldown, restarting soon")
    txt.clear_line(1)
    txt.printxy(1, 1, " Chat: <voting disabled>")

    txt.set_attr(True)
    txt.clear_line(4)
    txt.clear_line(5)
    txt.print_center(4, " Phase failed! ")
    txt.print_center(5, "No commands were proposed.")
    txt.set_attr(False)

  def setup_phase_presentation(self, cmds, min_votes):
    self.setup()

    for i, cmd in enumerate(cmds):
      section_name(1 + i * 3 + 0, f"!vote {i+1}")
      txt.printxy(0, 1 + i * 3 + 1, cmd)

    self.hide_time()
    txt.set_attr(True)
    txt.clear_line(0)
    txt.print_center(0, "Vote now using: !vote number")
    txt.set_attr(False)
    txt.printxy(0, 13, f"Required: {min_votes} votes")

  def reset_cmd(self, vote_duration):
    self.end_time = time.time() + vote_duration
    self.last_time = None
    self.cmd_counter = 0
    self.last_cmd_counter = None

  def update_cmd_count(self, cmd_count):
    self.cmd_counter = cmd_count

  def anim_cmd_counter(self):
    if self.cmd_counter != self.last_cmd_counter:
      self.last_cmd_counter = self.cmd_counter

    txt.clear_line(5)
    txt.print_center(5, f"{self.cmd_counter}")

  def setup_phase_vote(self):
    self.setup()

    txt.printxy(1, 0, "Phase: Voters vote on commands")
    txt.printxy(1, 1, " Chat: !vote id")
    txt.printxy(1, 2, " Time:")

    section_name(4, "Voting")
    section_name(10, "Command ?/?")

  def setup_phase_vote_failed(self, vote_req, vote_count, next_vote_req):
    self.setup()

    txt.printxy(1, 0, "Phase: Cooldown, restarting soon")
    txt.printxy(1, 1, " Chat: <voting disabled>")
    txt.printxy(1, 2, " Time: (restarting soon)")

    txt.set_attr(True)
    txt.clear_line(4)
    txt.clear_line(5)
    txt.print_center(4, " Phase failed! ")
    txt.print_center(5, "Too few votes.")
    txt.set_attr(False)

    section_name(7, "Voting rules")
    txt.printxy(1, 8, f" Required: {vote_req} votes")
    txt.printxy(1, 9, f" Received: {vote_count} votes")
    txt.printxy(1, 10, f"Next req.: {next_vote_req} votes")

  def setup_phase_vote_success(self, cmd, winner, total, next_vote_req):
    self.setup()

    txt.printxy(1, 0, "Phase: Cooldown, restarting soon")
    txt.printxy(1, 1, " Chat: <voting disabled>")
    txt.printxy(1, 2, " Time: (restarting soon)")

    section_name(4, "Winner")
    txt.printxy(0, 5, cmd)

    section_name(8, "Voting rules")
    txt.printxy(1, 9, f" Received: {total} votes")
    txt.printxy(1, 10, f"Next req.: {next_vote_req} votes")

  def anim_timer(self):
    now = time.time()
    delta = int(self.end_time - now)
    if delta < 0:
      delta = 0

    if delta == self.last_time:
      return

    self.last_time = delta
    txt.clear_line(2)
    txt.printxy(1, 2, f" Time: {delta} sec")

  def render_commands(self):
    cmd_id = self.command_shown + 1
    cmd = self.commands[self.command_shown]
    cmd_count = len(self.commands)

    txt.clear_line(10)
    txt.clear_line(11)
    txt.clear_line(12)
    section_name(10, f"Command {cmd_id}/{cmd_count}")
    txt.printxy(0, 11, cmd)

  def anim_command(self):
    now = time.time()
    if now - self.commands_last_update < self.command_shown_duration:
      return

    self.commands_last_update = now
    count = len(self.commands)

    if self.vote_winner is not None and 0 <= self.vote_winner < count:
      self.command_shown = self.vote_winner
    else:
      self.command_shown = (self.command_shown + 1) % count

    self.render_commands()

  def render_vote_chart(self, procents):
    line_sz = 24

    for i, pro in enumerate(procents):
      chart_sz = int((pro * line_sz * 8) / 100)
      selected = (self.vote_winner == i)
      s = f"{i+1}: "
      for j in range(chart_sz // 8):
        s += '\x18\x08'[selected]

      left = chart_sz % 8
      if left:
        s += chr(left + [0x10, 0x00][selected])

      s += f" {int(pro)}%"
      txt.clear_line(5 + i)
      txt.printxy(2, 5 + i, s)

  def reset_vote_chart(self, cmds, vote_duration):
    count = len(cmds)
    self.vote_chart_last_update = time.time()
    self.vote_winner = None
    self.final_procents = [0.0] * count
    self.anim_procents = [0.0] * count
    self.start_procents = [0.0] * count
    self.total_vote_count = 0
    self.commands = cmds[:]
    self.commands_last_update = time.time()
    self.command_shown = 0
    self.end_time = time.time() + vote_duration
    self.last_time = None

  def select_vote_winner(self, winner_id):
    self.vote_winner = winner_id

  def update_vote_chart(self, vote_counts):
    # Called when new data is available. This doesn't really render anything.
    self.vote_chart_last_update = time.time()

    sum_of_votes = sum(vote_counts)
    self.total_vote_count = sum_of_votes
    if sum_of_votes == 0:
      return

    for i, v in enumerate(vote_counts):
      self.start_procents[i] = self.anim_procents[i]
      self.final_procents[i] = (100.0 * v) / sum_of_votes

  def anim_vote_chart(self):
    now = time.time()
    delta = now - self.vote_chart_last_update
    total = self.anim_duration
    progress = delta / total
    if progress > 1.0:
      progress = 1.0

    for i in range(len(self.final_procents)):
      delta_pro = self.final_procents[i] - self.start_procents[i]
      self.anim_procents[i] = self.start_procents[i] + delta_pro * progress

    self.render_vote_chart(self.anim_procents)
    if self.total_vote_count == 0:
      section_name(4, f"Voting")
    elif self.total_vote_count == 1:
      section_name(4, f"Voting (1 vote)")
    else:
      section_name(4, f"Voting ({self.total_vote_count} votes)")

  def show_time(self):
    now = time.time()
    if now < self.last_time_shown + 0.1:
      return

    dots = bool(int(now) & 1)

    if dots:
      t = datetime.datetime.now().strftime("%H:%M:%S")
    else:
      t = datetime.datetime.now().strftime("%H %M %S")

    txt.set_attr(True)
    txt.printxy(0, H - 1, f" {t} \x0c")
    txt.set_attr(False)

  def hide_time(self):
    self.last_time_shown = 0

  def anim_phase_voting(self):
    self.anim_timer()
    self.anim_vote_chart()
    self.anim_command()
    self.show_time()

  def anim_phase_cmd(self):
    self.anim_cmd_counter()
    self.anim_timer()
    self.show_time()

  def sleep_anim(self, duration):
    now = time.time()
    self.end_time = now + duration

    while now < self.end_time:
      self.anim_timer()
      time.sleep(0.2)
      now = time.time()
      self.show_time()

def main():
  badlang_filter_load()

  # Setup the screen.
  global txt
  txt = textbuffer.TextBuffer(23401)
  txt.set_show_alive(True)
  txt.set_cursor_visibility(False)

  global basic_socket
  basic_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

  # XXX
  """
  scene_voting = SceneVoting()

  cmds = [
    "RUN",
    "10 PRINT \"HELLO WORLD\"",
    "LIST 30-100",
    "100 IF A=10 THEN X=A+B*X+PEEK(123) ELSE X=A+12",
  ]
  scene_voting.setup_phase_presentation(cmds)

  time.sleep(5)
  return
  """

  """
  scene_voting = SceneVoting()
  scene_voting.setup_phase_cmd()
  scene_voting.reset_cmd(10.0)
  vote_end = time.time() + 10.0
  cmd_count = 0
  while True:
    now = time.time()
    if now > vote_end:
      break

    if random.randint(0, 20) == 0:
      cmd_count += 1
      scene_voting.update_cmd_count(cmd_count)

    scene_voting.anim_phase_cmd()
    time.sleep(0.10)

  time.sleep(2)
  #scene_voting.setup_phase_cmd_failed()
  #time.sleep(2)

  scene_voting.setup_phase_vote()
  rand_time = time.time()
  votes = [0, 0, 0, 0]
  cmds = [
    "RUN",
    "10 PRINT \"HELLO WORLD\"",
    "100 IF A=10 THEN X=A+B*X+PEEK(123) ELSE X=A+12",
    "LIST 30-100"
  ]

  vote_end = time.time() + 10.0
  scene_voting.reset_vote_chart(cmds, 10.0)
  winner_set = False
  while True:
    now = time.time()
    if now > vote_end:
      if not winner_set:
        break
        #winner_set = True
        #scene_voting.select_vote_winner(random.randint(0, 3))
    elif now - rand_time > 3.0:  # Seconds.
      rand_time = now
      for i in range(len(votes)):
        votes[i] = random.randint(0, 1000)
      if sum(votes) == 0:
        votes[0] = 1
      scene_voting.update_vote_chart(votes)

    scene_voting.anim_phase_voting()
    time.sleep(0.05)

  scene_voting.setup_phase_vote_failed()
  time.sleep(10)
  return
  """
  # XXX

  scene_starting = SceneStarting()
  scene_starting.setup()

  # Ready the bot (blocking, might take a while).
  bot = VotingBot()

  while not bot.is_ready():
    scene_starting.anim()
    time.sleep(0.5)

  # In a loop count the votes in two phases.
  scene_voting = SceneVoting()
  scene_voting.setup()

  vote_requirement = VOTE_REQUIREMENT_START

  while True:
    api_stats = bot.yt.get_api_stats()
    print(
        f"note: YT API predicted calls per day: {api_stats['calls_per_day']} "
        f"(cost: {api_stats['calls_per_day'] * 5}, "
        f"cost from restart: {api_stats['calls_count'] * 5})"
    )

    # Command proposing phase.
    bot.set_delay(CMD_BOT_DELAY)
    bot.start_vote("!cmd")
    scene_voting.setup_phase_cmd(CMD_VOTE_DURATION)

    time.sleep(LAG)

    scene_voting.reset_cmd(CMD_VOTE_DURATION)
    vote_end = time.time() + CMD_VOTE_DURATION # + LAG
    vote_running = True
    cmd_count = 0
    last_cmd_count = 0
    cmds = set()
    while True:
      now = time.time()
      if now > vote_end:
        if vote_running:
          vote_running = False
          bot.set_delay(STOP_BOT_DELAY)
          bot.stop_vote()  # There still will be 1 final API call.
          vote_end = now + STOP_BOT_DELAY + 1.0
        else:
          break

      try:
        while True:
          org_cmd = bot.queue.get_nowait()
          cmd = org_cmd.split(maxsplit=1)
          if len(cmd) < 2:
            print(f"note: rejecting command (1) '{org_cmd}'")
            continue

          cmd = cmd[1]
          if len(cmd) > CMD_LENGTH_LIMIT:
            print(f"note: rejecting command (2) '{org_cmd}'")
            continue

          cmds.add(cmd)
      except queue.Empty:
        pass

      cmd_count = len(cmds)
      if cmd_count != last_cmd_count:
        last_cmd_count = cmd_count
        scene_voting.update_cmd_count(cmd_count)

      scene_voting.anim_phase_cmd()
      time.sleep(0.2)

    if cmd_count == 0:
      scene_voting.setup_phase_cmd_failed()
      scene_voting.sleep_anim(PHASE_FAIL_DELAY)
      continue

    cmds = list(cmds)
    if len(cmds) > 4:
      random.shuffle(cmds)
      cmds = cmds[:4]

    # Command presentation phase.
    bot.set_delay(CMD_PRESENTATION_DURATION)  # Wait with vote gathering.
    bot.start_vote("!vote")
    scene_voting.setup_phase_presentation(cmds, vote_requirement)
    time.sleep(CMD_PRESENTATION_DURATION)

    # Command voting phase.
    scene_voting.setup_phase_vote()
    scene_voting.anim_duration = VOTE_BOT_DELAY
    bot.set_delay(VOTE_BOT_DELAY)
    vote_end = time.time() + VOTE_VOTE_DURATION # + LAG
    scene_voting.reset_vote_chart(cmds, VOTE_VOTE_DURATION)
    winner_set = False
    vote_running = True
    votes = [0] * len(cmds)
    vote_count = 0
    last_vote_count = 0
    while True:
      now = time.time()
      if now > vote_end:
        if vote_running:
          vote_running = False
          bot.set_delay(STOP_BOT_DELAY)
          bot.stop_vote()
          vote_end = now + STOP_BOT_DELAY + 1.0
          scene_voting.anim_duration = 1.0
        elif not winner_set:
          winner_set = True

          if vote_count > 0:
            max_value = max(votes)
            possible_winners = []  # In case of a tie.
            for i, v in enumerate(votes):
              if v != max_value:
                continue
              possible_winners.append(i)
            winner = random.choice(possible_winners)
            winner_votes = max_value
            winner_cmd = cmds[winner]

            scene_voting.select_vote_winner(winner)
            vote_end = now + VOTE_BOT_DELAY  # Wait for the animation to settle.
        else:
          break

      if not winner_set:
        try:
          while True:
            org_cmd = bot.queue.get_nowait()
            cmd = org_cmd.split(maxsplit=1)
            if len(cmd) != 2:
              print(f"note: rejecting vote (1) '{org_cmd}'")
              continue

            try:
              vote = int(cmd[1]) - 1
            except ValueError:
              print(f"note: rejecting vote (2) '{org_cmd}'")
              continue

            if vote < 0 or vote >= len(cmds):
              print(f"note: rejecting vote (3) '{org_cmd}'")
              continue

            votes[vote] += 1
            vote_count += 1
        except queue.Empty:
          pass

      if last_vote_count != vote_count:
        last_vote_count = vote_count
        scene_voting.update_vote_chart(votes)

      scene_voting.anim_phase_voting()
      time.sleep(0.05)

    if vote_count < vote_requirement:
      old_vote_requirement = vote_requirement
      vote_requirement -= VOTE_REQUIREMENT_STEP_DOWN
      if vote_requirement < VOTE_REQUIREMENT_MIN:
        vote_requirement = VOTE_REQUIREMENT_MIN
      scene_voting.setup_phase_vote_failed(
          old_vote_requirement, vote_count, vote_requirement
      )
      scene_voting.sleep_anim(PHASE_FAIL_DELAY)
      continue

    # Vote winner announcement.
    send_to_basic(winner_cmd)

    vote_requirement += VOTE_REQUIREMENT_STEP_UP
    if vote_requirement > VOTE_REQUIREMENT_MAX:
      vote_requirement = VOTE_REQUIREMENT_MAX

    scene_voting.setup_phase_vote_success(
        winner_cmd, winner_votes, vote_count, vote_requirement
    )

    scene_voting.sleep_anim(20)

if __name__ == "__main__":
  main()
