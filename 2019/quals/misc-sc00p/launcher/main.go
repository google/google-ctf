/*
Copyright 2019 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package main

import (
	"bufio"
	"bytes"
	b64 "encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
)

var verbose = false
var writeableFilePath = "/bob/generatereport"

var bobsKeyFilePath = "/bob/id_rsa_bob"

// This is a fake key that means NOTHING! We just use it so we can run scp without sshpass
var bobsKey = `
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEA0Zt7E0bkaE2FYaCRv6G9EbWPDn8khJ4ltiPb1tdBJLlBAwzAlNEm
K1sFOL5gtd2b8cdQfvyc113o2XHz+qrRRKm2t3760zps0GJvdkkNAeuhnD+P5XnFF/rosH
V1pYJ51SvE/c+YyqQRGD4Li0txblzUmRWbEME6uiPYZJz+K8DPIIk0MZxDsVU1SIhSMAeQ
boCALHLwsPDsra+8g2pbdr8DSsRBPFBubhvgsqtRniX2mzpCkJOsHNkKHrM/pSawC3Z8Gl
5ATuqaR/orV3YUMyl2kT26dpuSGhr4trXyhc+kIXrxOuYPCGnuzjCimSkbRlcAs4Cd1Mxn
eO5J/UM+HQAAA+DeKYj/3imI/wAAAAdzc2gtcnNhAAABAQDRm3sTRuRoTYVhoJG/ob0RtY
8OfySEniW2I9vW10EkuUEDDMCU0SYrWwU4vmC13Zvxx1B+/JzXXejZcfP6qtFEqba3fvrT
OmzQYm92SQ0B66GcP4/lecUX+uiwdXWlgnnVK8T9z5jKpBEYPguLS3FuXNSZFZsQwTq6I9
hknP4rwM8giTQxnEOxVTVIiFIwB5BugIAscvCw8Oytr7yDalt2vwNKxEE8UG5uG+Cyq1Ge
JfabOkKQk6wc2Qoesz+lJrALdnwaXkBO6ppH+itXdhQzKXaRPbp2m5IaGvi2tfKFz6Qhev
E65g8Iae7OMKKZKRtGVwCzgJ3UzGd47kn9Qz4dAAAAAwEAAQAAAQEAk6f6uGatSkip2E87
vQob3ZjPsP+h4wZhPIDgQeUbD9qs0JAwLeV0BQC2mfWKvTLiwxyMORiNCC4wdNWQcJnal4
sSmwsJeLlkpBtjt6jYT+0EyMQCAz6XuD/ZoUztVm2mk6OkvsN6N+4B2NkEWtkHjB466ahN
tyzXyP6tVps9deWzNZ0PbGBIAAcH+F292NKl366fK3/8o36jNM1cyrqT5Z++9BhoqPrX8I
Xi8meop+bV1p58j8aKUHlqB1ElRl+7WGefvC1qRtrwK6ICowyJ+2XM4o0j5O8WqdVNgDin
KeUUo5as73vgMndag3Q17KkYp9i7Bk24xh+sAJK19QkpRQAAAIBflIpIO0GCvZbnIbjIlQ
655w/x7yTEiX6ponMXY8kA5DQPz2hPgkP/0ZMlaOUvBC8kmcVseNFjhHlv73LtUO7aULO3
4kixiOw3E18H+L9xIeASfpg7FTfXQoM3G4XxFa0rGInRU0EgRV1eRm5ouXO+9179I5nMSB
bmkFyQPNTNPwAAAIEA9zAlAkaKAtFriyO48K9STz6B1Wtk5eQklO3I1uqJaFcQGDmG8gHs
r/sITkkBivQhSgOi3B17mQ6XFgxVXtQImIl3dJSm8eayxMVWen8e0lYHBDrqttshpqPQB3
CO6Rnjx7dULlOBX67j92jEcu2VFGRsQdim4ziy04ypzTg2CgcAAACBANkUXziJYpmBb3ZH
RNMaENPvtTZKPUqFfg8ULbW515pOl1TvXM/+ccdsy3pHZvwxe2PwGxbl+JVZN7V2stNcki
WAuf9xuaTPI6ZXNCk2QcrFuAeA7VH+BKB1rWveEJf8/ZMYBA6qXuRhidevVaeIlURpPLPe
sGl91oD2gV6W1/27AAAAJWRkbWFzc2V5QGRkbWFzc2V5LmF1cy5jb3JwLmdvb2dsZS5jb2
0BAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
`

var welcomeMessage = `
Hi Alice,

Put in your ip address here and I'll pull the file from you on our usual ssh port and execute my job to call you back with the results.

Thanks,
Bob
`

func pullFileOverScp(ipAddress, username string) error {
	var err error
	srcParameter := fmt.Sprintf("%s@%s:data.txt", username, ipAddress)

	params := []string{
		"-i",
		"/bob/id_rsa_bob",
		"-P",
		"2222",
		"-o",
		"StrictHostKeyChecking=no",
		"-o",
		"ConnectTimeout=5",
		srcParameter,
		"/bob",
	}
	cmd := exec.Command("/usr/bin/scp", params...)

	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb

	err = cmd.Run()

	if verbose {
		fmt.Printf("sshpass cmd:%+v\n", cmd)
		fmt.Printf("stdout:%s\nstderr:%s\n", outb.String(), errb.String())
		fmt.Printf("err:%v\n", err)
		dumpBobDirectory()
	}

	return nil
}

func dumpBobDirectory() {
	files, err := ioutil.ReadDir("/bob")
	if err == nil {
		fmt.Println("Files in /bob")
		for _, f := range files {
			fmt.Printf("name: %s size: %d\n", f.Name(), f.Size())
			if f.Size() < 1000 {
				content, err := ioutil.ReadFile("/bob/" + f.Name())
				if err == nil {
					fmt.Println("CONTENTS:")
					fmt.Printf(string(content))
					fmt.Println("======")
				}
			}
		}
	}
}

func runGenerateReport(ipAddress string) {

	params := []string{ipAddress}

	cmd := exec.Command("/bob/generatereport", params...)

	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb

	err := cmd.Run()

	if verbose {
		fmt.Printf("generatereport cmd:%+v\n", cmd)
		fmt.Printf("stdout:%s\nstderr:%s\n", outb.String(), errb.String())
		fmt.Printf("err:%v\n", err)
	}
}

func main() {

	flag.BoolVar(&verbose, "verbose", false, "enable verbose output for debugging")

	flag.Parse()

	sDec, _ := b64.StdEncoding.DecodeString(GenerateReportProgram)
	err := ioutil.WriteFile(writeableFilePath, sDec, 0755)
	if err != nil {
		if verbose {
			fmt.Printf("Failure writing default generateprogram executable. err:%v\n", err)
		}
		os.Exit(1)
	}

	err = ioutil.WriteFile(bobsKeyFilePath, []byte(bobsKey), 0600)
	if err != nil {
		if verbose {
			fmt.Printf("Failure writing Bob's key. err:%v\n", err)
		}
		os.Exit(2)
	}

	if verbose {
		dumpBobDirectory()
	}

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Println(welcomeMessage)
		scanner.Scan()
		line := scanner.Text()
		if line == "exit" {
			os.Exit(0)
		}
		ip := net.ParseIP(line)
		if ip == nil {
			continue
		}
		pullFileOverScp(ip.String(), "bob")
		runGenerateReport(ip.String())
		fmt.Println()
	}

	if scanner.Err() != nil {
		if verbose {
			fmt.Println(scanner.Err())
		}
		os.Exit(3)
	}
}
