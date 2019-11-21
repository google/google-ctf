/******************************************************************************
 * Copyright 2018 Google
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *****************************************************************************/

// Quick and hacky script to play certian sounds on certain events.
// Requires `GOOGLE_APPLICATION_CREDENTIALS` to point to valid credentials,
// `mpv` and some sound files to play in the current directory.
package main

import (
	"context"
	"log"
	"os"
	"strings"

	"cloud.google.com/go/pubsub"
)

func play_sound(s string, max_vol bool) {
	var procAttr os.ProcAttr
	var vol_str string
	if max_vol {
		vol_str = "--volume=100"
	} else {
		vol_str = "--volume=50"
	}
	cmd := []string{"/usr/bin/mpv", s + ".mp3", vol_str}
	os.StartProcess(cmd[0], cmd, &procAttr)
}

func main() {
	projectID := "SNIP"
	subscription_name := "SNIP"

	ctx := context.Background()

	client, err := pubsub.NewClient(ctx, projectID)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	sub := client.Subscription(subscription_name)
	err = sub.Receive(ctx, func(ctx context.Context, m *pubsub.Message) {
		log.Printf("Got message: %s", m.Data)
		s := string(m.Data)

		if s == "explode" || s == "incorrect_password" || s == "correct_password" {
			play_sound(s, s == "explode")
		} else if strings.HasPrefix(s, "defuse") {
			play_sound("defused", false)
		} else {
			log.Printf("UNKNOWN data")
		}
		m.Ack()
	})

	if err != nil {
		log.Fatalf("Could not receive: %v", err)
	}
}
