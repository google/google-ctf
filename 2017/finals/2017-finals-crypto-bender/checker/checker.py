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

"""
This is the stdio program that verifies a submitted will.  It reads the
submitted will from stdin.  If the will is different than the original,
yet has the same hash digest, then we print a success message that includes the
CTF flag.  Otherwise we print a failure message.

This program should be run once per submission.  It exits after printing the
result message to stdout.
"""

import hasher
import json
import sys

with open("metadata.json", "r") as jsonFile, open("farnsworth_fry_will", "rb") as willFile:
  print "Welcome to the will authenticity checker service."
  print "Please provide the will from Professor Herbert J. Farnsworth:"
  sys.stdout.flush()
  data = json.load(jsonFile)
  flag = data['challenge']['flag'].strip().encode()
  originalWill = willFile.read()
  originalHash = hasher.findDigest(originalWill)
  newWill = sys.stdin.read(len(originalWill))
  if newWill == originalWill:
    print "The new will must be different than the original."
    sys.exit(0)
  newHash = hasher.findDigest(newWill)
  if newHash != originalHash:
    print "The new hash does not match the original."
    print "The original hash is: %064x" % originalHash
    print "The new hash is:      %064x" % newHash
    sys.exit(0)
  print "Success!  You, Bender the robot, inherit everything, and Fry gets nothing."
  print "Among the professor's notes that you inherited, you found:"
  print flag
