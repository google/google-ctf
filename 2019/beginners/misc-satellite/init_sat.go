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

import "net"
import "fmt"
import "bufio"
import "os"
import "regexp"
import "strings"
var flag string

func main() {
    fmt.Print("Hello Operator. Ready to connect to a satellite?\n")

  for { 
    // read input from stdin
    os_reader := bufio.NewReader(os.Stdin)
    fmt.Print("Enter the name of the satellite to connect to or 'exit' to quit\n")
    text, _ := os_reader.ReadString('\n')

    switch strings.ToLower(text) {
    case "osmium\n":
	    connectToSat(text)

    case "exit\n":
            fmt.Println("Exiting, goodbye")
	    return
    default:
	    fmt.Println("Unrecognized satellite: " + text)
    }
  }
}
func connectToSat(sat string) {

    fmt.Println("Establishing secure connection to " + sat + " satellite...")
    conn, err := net.Dial("tcp", "satellite.ctfcompetition.com:1337")

    if err != nil {
	    fmt.Println("Can't connect to the satellite. Please contact the Google CTF team.")
	    os.Exit(0)
    }

    for {
	conn_reader := bufio.NewReader(conn)
	message, err := conn_reader.ReadString('\n')
	if err != nil {
		// this triggers if the satellite terminates the connection. Breaking out of the loop in this case.
		break
	}
	regex := regexp.MustCompile("CTF{\\S{40}}")
	// sanitize output
	fmt.Println(regex.ReplaceAllString(message, "********************"))

        os_reader := bufio.NewReader(os.Stdin)
        text, err := os_reader.ReadString('\n')
	if err != nil {
		fmt.Println(err)
	}
	conn.Write([]byte(text))

	if err != nil {
		break
        }
     }
     conn.Close()
}

