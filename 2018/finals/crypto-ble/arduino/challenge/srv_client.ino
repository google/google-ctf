/*
Copyright 2018 Google LLC

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

#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>

static BLEUUID serviceUUID("1337c74a-7402-4785-a9fa-54d92fd91c56");
static BLEUUID    charUUID("1337e166-5f58-403d-96b4-97d1ec25a147");

static BLEAddress *pServerAddress;
static boolean doConnect = false;
static boolean connected = false;
static BLERemoteCharacteristic* pRemoteCharacteristic;
static BLEClient*  pClient;

bool connectToServer(BLEAddress pAddress);


bool connectToServer(BLEAddress pAddress) {
  Serial.print("Forming a connection to ");
  Serial.println(pAddress.toString().c_str());

  // Connect to the remove BLE Server.
  pClient->connect(pAddress);
  Serial.println(" - Connected to server");

  // Obtain a reference to the service we are after in the remote BLE server.

  auto services = pClient->getServices();
  if (services->empty()) {
    Serial.println("No services found");
    return false;
  } else {
    for (auto &myPair : *services) {
      Serial.println(("Service " + myPair.first).c_str());
    }
  }

  BLERemoteService* pRemoteService = pClient->getService(serviceUUID);
  if (pRemoteService == nullptr) {
    Serial.print("Failed to find our service UUID: ");
    Serial.println(serviceUUID.toString().c_str());
    return false;
  }
  Serial.println(" - Found our service");

  // Obtain a reference to the characteristic in the service of the remote BLE server.
  pRemoteCharacteristic = pRemoteService->getCharacteristic(charUUID);
  if (pRemoteCharacteristic == nullptr) {
    Serial.print("Failed to find our characteristic UUID: ");
    Serial.println(charUUID.toString().c_str());
    return false;
  }
  Serial.println(" - Found our characteristic");

  // Read the value of the characteristic.
  pRemoteCharacteristic->writeValue(0, true);
  std::string value = pRemoteCharacteristic->readValue();
  Serial.print("The characteristic value was: ");
  Serial.println(value.c_str());

  //pRemoteCharacteristic->registerForNotify(notifyCallback);
  return true;
}

class MyAdvertisedDeviceCallbacks: public BLEAdvertisedDeviceCallbacks {

    void onResult(BLEAdvertisedDevice advertisedDevice) {
      Serial.print("BLE Advertised Device found: ");
      Serial.println(advertisedDevice.toString().c_str());

      if (advertisedDevice.haveServiceUUID() && advertisedDevice.getServiceUUID().equals(serviceUUID)) {
        Serial.print("Found service,  address: ");
        advertisedDevice.getScan()->stop();

        if (pServerAddress) {
          delete pServerAddress;
          pServerAddress = NULL;
        }

        pServerAddress = new BLEAddress(advertisedDevice.getAddress());
        doConnect = true;
      }
    }
};


void client_setup() {
  BLEDevice::init("");
  BLEDevice::setMTU(350);

  pClient  = BLEDevice::createClient();

  BLEScan* pBLEScan = BLEDevice::getScan(); //create new scan
  pBLEScan->setAdvertisedDeviceCallbacks(new MyAdvertisedDeviceCallbacks());
  pBLEScan->setActiveScan(true); //active scan uses more power, but get results faster
  BLEScanResults foundDevices = pBLEScan->start(20);
  Serial.print("Devices found: ");
  Serial.println(foundDevices.getCount());
  Serial.println("Scan done!");

}

void client_loop() {
  unsigned char *buff = new unsigned char[1024];

  if (connected) {
    CryptoService cs = CryptoService(false);
    unsigned long len = 1024;

    digitalWrite(LED_BUILTIN, HIGH);

    memset(buff, 0, 1024);
    cs.writePubKey(buff, &len);
    pRemoteCharacteristic->writeValue(buff, len);
    delay(300);

    std::string value = pRemoteCharacteristic->readValue();
    const unsigned char *data = (unsigned char*)value.c_str();
    int length = value.size();
#ifdef DEBUG
    printf("recv "); print_hex(data, length);
#endif
    if (length < 1 || data[0] != PARAMS) goto err;
    if (cs.readKey(data + 1, length - 1) != CRYPT_OK) goto err;
    if (cs.calcSecret() != CRYPT_OK) goto err;

    cs.setExchanged(true);


    buff[0] = NONCE;
    *(unsigned int*)(buff + 1) = cs.getNonce();
    pRemoteCharacteristic->writeValue(buff, 5);
    delay(300);

    value = pRemoteCharacteristic->readValue();
    data = (unsigned char*)value.c_str();
    length = value.size();
#ifdef DEBUG
    printf("recv "); print_hex(data, length);
#endif
    if (length < 1 || data[0] != NONCE) goto err;
    cs.setOtherNonce(*(unsigned int*)(data + 1));

    len = 1024;
    cs.writeProof(buff, &len);
    pRemoteCharacteristic->writeValue(buff, len);
    delay(300);

    value = pRemoteCharacteristic->readValue();
    data = (unsigned char*)value.c_str();
    length = value.size();
#ifdef DEBUG
    printf("recv "); print_hex(data, length);
#endif

    if (length < 1 || data[0] != PROOF) goto err;
    if (!cs.verifyOtherProof(data + 1, length - 1)) goto err;

    buff[0] = FLAG;
    pRemoteCharacteristic->writeValue(buff, 1);
    delay(300);

    value = pRemoteCharacteristic->readValue();
    data = (unsigned char*)value.c_str();
    length = value.size();
#ifdef DEBUG
    printf("recv "); print_hex(data, length);
#endif

    len = length > 1024 ? 1024 : length;
    memcpy(buff, data, len);
    if (cs.decrypt(buff + 1, len - 1, buff, &len) == CRYPT_OK) {
#ifdef DEBUG
      dbgprintf("decrypted ");
      print_hex(buff, len);
#endif
      if (memcmp(buff, "CTF{", 4) == 0) {
        Serial.println("Got flag!");
      } else {
        Serial.println("wrong flag");
      }

    } else {
      Serial.println("can't decrypt flag");
    }

err:
    Serial.println("bye bye");
    pClient->disconnect();
    connected = false;
    digitalWrite(LED_BUILTIN, LOW);

    //delay(5000);
    //BLEDevice::getScan()->start(20);
  } else if (doConnect) {
    if (connectToServer(*pServerAddress)) {
      Serial.println("Connected to Server.");
      connected = true;
    }
    doConnect = false;
  } else {
    delay(5000);
    BLEDevice::getScan()->start(20);
  }
  
  delete[] buff;
}
