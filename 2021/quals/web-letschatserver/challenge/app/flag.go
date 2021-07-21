/**
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package main

import (
	"bufio"
	"fmt"
	"strings"
)

type message struct {
	user string
	text string
}

type Flag struct {
	messages []*message
	tracker  int
	b        *Batch
}

func (f *Flag) Reset() error {
	thisMsg := f.messages[f.tracker]
	f.tracker = (f.tracker + 1) % len(f.messages)
	toSend := &MessageRow{
		To:      "you aren't supposed to guess this value...",
		Message: fmt.Sprintf("%s:%s", thisMsg.user, thisMsg.text),
	}
	f.b.Add(toSend)
	return nil
}

func NewFlag(b *Batch) *Flag {
	convo := `Cthon98:hey, if you type in your pw, it will show as stars
Cthon98:********* see!
AzureDiamond:FLAG_PART_1[ctf{chat]
AzureDiamond:doesnt look like stars to me
Cthon98:AzureDiamond *******
Cthon98:thats what I see
AzureDiamond:oh, really?
Cthon98:Absolutely
AzureDiamond:you can go FLAG_PART_2[your] my FLAG_PART_3[way]-ing FLAG_PART_4[to]
AzureDiamond:haha, does that look funny to you?
Cthon98:lol, yes. See, when YOU type FLAG_PART_5[the], it shows to us as *******
AzureDiamond:thats neat, I didnt know Lack did that
Cthon98:yep, no matter how many times you type FLAG_PART_6[winning], it will show to us as *******
AzureDiamond:awesome!
AzureDiamond:wait, how do you know my pw?
Cthon98:er, I just copy pasted YOUR ******'s and it appears to YOU as FLAG_PART_7_FINAL_PART[flag}] cause its your pw
AzureDiamond:oh, ok.`

	flagMessages := []*message{}
	scanner := bufio.NewScanner(strings.NewReader(convo))
	for scanner.Scan() {
		split := strings.Split(scanner.Text(), ":")
		flagMessages = append(flagMessages, &message{user: split[0], text: split[1]})
	}

	return &Flag{
		messages: flagMessages,
		tracker:  0,
		b:        b,
	}
}
