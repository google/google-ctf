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

package main

import "bufio"
import "fmt"
import "os"
var config_data = "Username: " + username + " password: " + flag + "\t166.00 IS-19 2019/05/09 00:00:00\tSwath 640km\tRevisit capacity twice daily, anywhere Resolution panchromatic: 30cm multispectral: 1.2m\tDaily acquisition capacity: 220,000km²\tRemaining config data written to: " + file + "\n"
var username = "brewtoot"
var flag = "CTF{4efcc72090af28fd33a2118985541f92e793477f}"
var file = "https://docs.google.com/document/d/14eYPluD_pi3824GAFanS29tWdTcKxP_XUxx7e303-3E"
var instructions = "Enter (a) to display config data, (b) to erase all data or (c) to disconnect\n"

func main() {
  serveClient()
}

func serveClient () {
	reader := bufio.NewReader(os.Stdin)
  os.Stdout.Write([]byte("Welcome. " + instructions + "\n"))
  // run loop forever (or until ctrl-c)
  for {
    // will listen for message to process ending in newline (\n)
    message, err := reader.ReadString('\n')
    switch message {
	case "a\n":
		os.Stdout.Write([]byte(config_data))
	case "b\n":
		os.Stdout.Write([]byte("Insufficient privileges.\n"))
	case "c\n":
		os.Stdout.Write([]byte("Disconnecting, goodbye.\n"))
		os.Exit(0)
	default:
		os.Stdout.Write([]byte(instructions+"\n"))
    }
    if err != nil {
	    fmt.Println(err)
	    return
    }
  }
}
