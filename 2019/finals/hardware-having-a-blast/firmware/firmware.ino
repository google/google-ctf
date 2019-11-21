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
#include "esp32-mqtt.h"
#include "config.h"
#include "display.h"
#include "bomb.h"

hw_timer_t *spkr_timer = nullptr;
Bomb *bomb = nullptr;
Bomb *create_bomb();

void messageReceived(String &topic, String &payload) {
  Serial.println("incoming: " + topic + " - " + payload);
  if (payload == "RESET") {
    Bomb *bomb2 = create_bomb();

    // We are leaking memory here on purpose to avoid crashing. This should be
    // good enough so that we can keep the code simple.
    bomb = bomb2;
  } else if (payload == "START") {
    if (bomb) {
      bomb->skip_lightsensor();
    }
  } else if (payload == "DEFUSE") {
    if (bomb) {
      bomb->defuse();
    }
  } else {
    // Nothing
  }
}

TaskHandle_t task_mqtt_client;
TaskHandle_t task_bomb;

// Set event_to_send first, then set send_event = true.
bool send_event = false;
String event_to_send;

void mqtt_loop(void *) {
  setupCloudIoT();
  while (true) {
    mqttClient->loop();
    delay(10);  // <- fixes some issues with WiFi stability

    if (!mqttClient->connected()) {
      connect();
    }

    if (send_event) {
      publishTelemetry(event_to_send);
      send_event = false;
    }
  }
}

void bomb_loop(void *) {
  while (true) {
    bomb = create_bomb();
    if (!bomb) {
      Serial.println("I was unable to create a bomb!");
    } else {
      while (true) {
        bomb->tick();
        delay(1);
      }
    }
  }
}

int disable_spkr_in = 0;
portMUX_TYPE mux = portMUX_INITIALIZER_UNLOCKED;

void onSpkrTimer() {
  portENTER_CRITICAL(&mux);
  static bool state = false;
  state = !state;
  digitalWrite(SPEAKER_PIN, state);
  if (--disable_spkr_in == 0) {
    timerAlarmDisable(spkr_timer);
    timerStop(spkr_timer);
  }
  portEXIT_CRITICAL(&mux);
}

void setup() {
  Serial.begin(115200);
  pinMode(STROBE_PIN, OUTPUT);
  pinMode(DATA_PIN, OUTPUT);
  pinMode(CLK_PIN, OUTPUT);

  pinMode(LIGHT_SENSOR_PIN, INPUT);
  pinMode(WIRE1_PIN, INPUT);
  pinMode(WIRE2_PIN, INPUT);
  pinMode(DO_PASSWORD_CHECK_PIN, INPUT);
  pinMode(CLOCK_IN_PIN, INPUT);
  pinMode(PASSWORD_PIN, INPUT);
  pinMode(SPEAKER_PIN, OUTPUT);

  // Enable pull-up
  digitalWrite(LIGHT_SENSOR_PIN, HIGH);
  digitalWrite(WIRE1_PIN, HIGH);
  digitalWrite(WIRE2_PIN, HIGH);
  digitalWrite(DO_PASSWORD_CHECK_PIN, HIGH);
  digitalWrite(CLOCK_IN_PIN, HIGH);
  digitalWrite(PASSWORD_PIN, HIGH);
  digitalWrite(SPEAKER_PIN, HIGH);

  Display::init();
  Display::clear(true);

  spkr_timer = timerBegin(0, 80, true);
  timerAttachInterrupt(spkr_timer, &onSpkrTimer, true);
  timerAlarmWrite(spkr_timer, 500, true);

  // Spawn two threads:
  //  - WiFi/MQTT handling code
  //  - Application logic
  auto a = xTaskCreatePinnedToCore(
    mqtt_loop,
    "MQTT",
    10000, // stack size
    nullptr, // arg
    1, // priority
    &task_mqtt_client,
    0  // pin to core 0
  );

  auto b = xTaskCreatePinnedToCore(
    bomb_loop,
    "bomb",
    1000, // stack size
    nullptr, // arg
    1, // priority
    &task_bomb,
    1  // pin to core 1
  );

  if (a != pdPASS || b != pdPASS) {
    Serial.println("Some error occured");
  } else {
    Serial.println("Tasks initialized");
  }
}

Bomb *create_bomb() {
  Bomb *my_bomb = new Bomb;
  my_bomb->set_on_explode([]() {
    event_to_send = "explode";
    send_event = true;
  });
  my_bomb->set_on_defuse([]() {
    static char buf[64];
    sprintf(buf, "defuse:%d", bomb->time_remaining());
    event_to_send = buf;
    send_event = true;
  });

  return my_bomb;
}

void loop() {
    // Empty
}
