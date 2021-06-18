// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package main;

import (
    "fmt";
    "os";
    "bufio";
)


func main() {
	flag := []byte{'K', 'F', 'O', ';', '~', 'D', 'w', 'b', 'o', 'h', 'd', 'v', 'w', 'b', 'w', 'k', 'h', 'u', 'h', 'b', 'z', 'h', 'u', 'h', 'b', 'v', '|', 'p', 'e', 'r', 'o', '}', '\x80'}
		fmt.Print(`
      ___           ___           ___           ___           ___           ___     
     /  /\         /  /\         /  /\         /  /\         /  /\         /  /\    
    /  /:/_       /  /::\       /  /:/_       /  /::\       /  /:/_       /  /::\   
   /  /:/ /\     /  /:/\:\     /  /:/ /\     /  /:/\:\     /  /:/ /\     /  /:/\:\  
  /  /:/_/::\   /  /:/  \:\   /  /:/_/::\   /  /:/  \:\   /  /:/_/::\   /  /:/  \:\ 
 /__/:/__\/\:\ /__/:/ \__\:\ /__/:/__\/\:\ /__/:/ \__\:\ /__/:/__\/\:\ /__/:/ \__\:\
 \  \:\ /~~/:/ \  \:\ /  /:/ \  \:\ /~~/:/ \  \:\ /  /:/ \  \:\ /~~/:/ \  \:\ /  /:/
  \  \:\  /:/   \  \:\  /:/   \  \:\  /:/   \  \:\  /:/   \  \:\  /:/   \  \:\  /:/ 
   \  \:\/:/     \  \:\/:/     \  \:\/:/     \  \:\/:/     \  \:\/:/     \  \:\/:/  
    \  \::/       \  \::/       \  \::/       \  \::/       \  \::/       \  \::/   
     \__\/         \__\/         \__\/         \__\/         \__\/         \__\/
	 `)
    fmt.Print("> ");
    user_input,_,err := bufio.NewReader(os.Stdin).ReadLine();
    if err != nil {
			return
    }
		if len(user_input) != len(flag) {
				fmt.Println("nope.");
				return
		}
		for i, char := range user_input {
			if flag[i] != char + 3 {
				fmt.Println("nope.");
				return
			}
		}
		fmt.Printf("flag: %s\n", string(user_input))
}
