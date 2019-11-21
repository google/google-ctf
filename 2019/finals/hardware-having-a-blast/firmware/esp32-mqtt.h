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
// See https://github.com/GoogleCloudPlatform/google-cloud-iot-arduino/blob/master/examples/Esp32-lwmqtt/
// This file contains static methods for API requests using Wifi / MQTT
#pragma once

#include <Client.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>

#include <MQTT.h>

#include <CloudIoTCore.h>
#include <CloudIoTCoreMqtt.h>
#include "ciotc_config.h" // Update this file with your configuration

// Initialize WiFi and MQTT for this board
Client *netClient = nullptr;
CloudIoTCoreDevice *device = nullptr;
CloudIoTCoreMqtt *mqtt = nullptr;
MQTTClient *mqttClient = nullptr;
unsigned long iss = 0;
String jwt;

///////////////////////////////
// Helpers specific to this board
///////////////////////////////
String getJwt() {
  iss = time(nullptr);
  Serial.println("Refreshing JWT");
  jwt = device->createJWT(iss, jwt_exp_secs);
  return jwt;
}

void setupWifi() {
  Serial.println("Starting wifi");

  WiFi.mode(WIFI_STA);
  WiFi.begin("GoogleGuest-Legacy");
  Serial.println("Connecting to WiFi");
  while (WiFi.status() != WL_CONNECTED) {
    delay(100);
  }

  configTime(0, 0, ntp_primary, ntp_secondary);
  Serial.println("Waiting on time sync...");
  while (time(nullptr) < 1510644967) {
    delay(10);
  }
}

void connectWifi() {
  int i = 0;
  Serial.print("checking wifi...");
  while (WiFi.status() != WL_CONNECTED) {
    Serial.print(".");
    delay(1000);
    i++;
    if (i == 20) {
      WiFi.begin("GoogleGuest-Legacy");
    }
  }
}

///////////////////////////////
// Orchestrates various methods from preceeding code.
///////////////////////////////

void publishTelemetry(String data) {
  mqtt->publishTelemetry(data);
}

void publishTelemetry(const char* data, int length) {
  mqtt->publishTelemetry(data, length);
}

void publishTelemetry(String subfolder, String data) {
  mqtt->publishTelemetry(subfolder, data);
}

void publishTelemetry(String subfolder, const char* data, int length) {
  mqtt->publishTelemetry(subfolder, data, length);
}

void connect() {
  connectWifi();
  mqtt->mqttConnect();
}

void setupCloudIoT() {
  device = new CloudIoTCoreDevice(
      project_id, location, registry_id, device_id,
      private_key_str);

  setupWifi();
  netClient = new WiFiClientSecure();
  mqttClient = new MQTTClient(512);
  mqttClient->setOptions(180, true, 1000);
  mqtt = new CloudIoTCoreMqtt(mqttClient, netClient, device);
  mqtt->setUseLts(true);
  mqtt->startMQTT();
}
