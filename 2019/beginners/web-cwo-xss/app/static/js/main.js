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

$(function() {


  $("#livestream-chat-form").on("submit", function(e){
    e.preventDefault();

    var val = $("#livestream-chat-input").val();
    let formData = new FormData();
    formData.append('message', val);

    fetch('/send', {
      method: "post",
      body: formData
    })
    .then(function(response) {
      var data = response.json().then(function(data){
        var profile_url = data["profile_url"];
        var username = data["username"];
        var message = data["message"];

        var html = `<div class="livestream-chat-item"> <div class="livestream-chat-profile"> <img src="` + profile_url + `" /> </div> <div class="livestream-chat-text"> <div class="livestream-chat-username"> ` + username + ` </div> <div class="livestream-chat-message"> ` + message + ` </div> </div> </div>`;

        $(".livestream-chat-list").append(html);
        $(".livestream-chat-list").scrollTop($(".livestream-chat-list").prop("scrollHeight"));
      });
    });

    $("#livestream-chat-input").val("");
  }); 

});
