// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.



#include <algorithm>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <stdlib.h>
#include <sstream>
#include <unistd.h>

#include "src/client/http_client.h"
#include "src/client/string_encoding.h"
#include "src/proto/aart_message.pb.h"

void generate_id(std::string& str_id) {
  srand(time(NULL) + getpid());
  for(int i = 0; i < 32; i++) {
  	char c = (rand() % 26) + 0x61;
  	str_id.push_back(c);
  }
}

void send_message(const std::string server_address,
                  const AartMessage& msg_to_send,
                  AartMessage& server_response) {
	std::stringstream ss;
	msg_to_send.SerializeToOstream(&ss);
	std::string encoded_proto = ss.str();

	std::string hex_encoded;
	StringEncoder str_encoder;
	str_encoder.encode_string(encoded_proto);

	std::string received_content;
	HttpSend(server_address.c_str(), "/", encoded_proto, received_content);

	std::string received_msg;
	received_msg.assign(received_content.substr(
		received_content.find("\r\n\r\n") + 4));

  str_encoder.decode_string(received_msg);

	server_response.ParseFromString(received_msg);
}

/*
  Process server response.
  If the server response is a list of capabilities, check it contains GET_IMAGE
  and send protobuf requesting image.

  If the server response is an image, print it to screen.

  Otherwise, return an empty string
*/
void process_message(const AartMessage& request_message, AartMessage& response_message) {
	if (request_message.type() == AartMessage_AartMessageType_R_CAPABILITIES &&
    request_message.content().find("GET_FLAG") != std::string::npos) {
		response_message.set_type(AartMessage_AartMessageType_R_OPERATION);
		response_message.set_client_id(request_message.client_id());
		response_message.set_content("GET_FLAG");
		return;
	}

	if (request_message.type() == AartMessage_AartMessageType_R_OPERATION_RESPONSE) {
		std::cout << request_message.content();
		return;
	}

	std::cout << "Unhandled message type!" << request_message.type() << request_message.content() << std::endl;
}

int main(int argc, char * argv[]) {
  if (argc != 2) {
    std::cout << "Missing server address!" << std::endl;
    return -1;
  }
  std::string server_address = argv[1];

  std::string client_id;
  generate_id(client_id);

  AartMessage client_request;
  client_request.set_type(AartMessage_AartMessageType_R_HELLO);
  client_request.set_client_id(client_id);
  client_request.set_content("HELLO");

  AartMessage received_content;
  send_message(server_address, client_request, received_content);

  AartMessage to_send;
  process_message(received_content, to_send);
  send_message(server_address, to_send, received_content);
  std::cout << received_content.content() << std::endl;
}
