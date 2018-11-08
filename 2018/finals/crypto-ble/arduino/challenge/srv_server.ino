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
#include <BLEServer.h>
#include <BLE2902.h>

#define SERVER_SERVICE_UUID        "1337c74a-7402-4785-a9fa-54d92fd91c56"
#define SERVER_CHARACTERISTIC_UUID "1337e166-5f58-403d-96b4-97d1ec25a147"


class ServerCharacteristic : public BLECharacteristic, public CryptoService {

  public:
    ServerCharacteristic(const char* uuid, uint32_t properties = 0) : BLECharacteristic(uuid, properties), CryptoService(true) {
    }

    ~ServerCharacteristic() {
    }
};

class ServerCallbacks: public BLEServerCallbacks {
    void onConnect(BLEServer* pServer) {
      Serial.println("got connection");
    };

    void onDisconnect(BLEServer* pServer) {
      pServer->startAdvertising();
    }
};

class ServerCharCallbacks : public BLECharacteristicCallbacks {
    unsigned char *buff;

    void process(ServerCharacteristic *c, const unsigned char *data, int length) {
      dbgprintf("process() %d ", length);

      switch (data[0]) {
        // Exchange PKs
        case PARAMS:
          {
            c->setExchanged(false);
            c->setAuthenticated(false);
            if (!c->readKey(data + 1, length - 1)) {
              long unsigned int len = 1024;
              memset(buff, 0, len);
              if (c->writePubKey(buff, &len) == CRYPT_OK && c->calcSecret() == CRYPT_OK) {
                c->setValue(buff, len);
                c->setExchanged(true);
              }
            }
            break;
          }
        case NONCE:
          if (c->exchangedKeys() && length == 5) {
            c->setOtherNonce(*(unsigned int*)(data + 1));
            buff[0] = NONCE;
            *(unsigned int*)(buff + 1) = c->getNonce();
            c->setValue(buff, 5);
          }
          break;
        // Verify nonce
        case PROOF:
          {
            if (c->exchangedKeys() && c->verifyOtherProof(data + 1, length - 1)) {
              long unsigned int len = 1024;
              c->getNonce();
              c->writeProof(buff, &len);
              c->setValue(buff, len);
            }
          }
          break;
        case FLAG:
          if (c->isAuthenticated()) {
            long unsigned int len = 1024;
            memset(buff, 0, len);
            c->writeFlag(buff, &len);
            c->setValue(buff, len);
          }
          break;
        default:
          break;
      }
    }

    void onRead(BLECharacteristic *pCharacteristic) {
    }

    void onWrite(BLECharacteristic *pCharacteristic) {
      dbgprintf("char onwrite %d\n", pCharacteristic->getValue().size());

      ServerCharacteristic *c = (ServerCharacteristic*)pCharacteristic;
      std::string value = c->getValue();
      const unsigned char *val = (unsigned char*)value.c_str();
      int length = value.size();

#ifdef DEBUG
      printf("received: ");
      print_hex(val, length);
#endif

      if (length < 1 || length > 1024) return;

      dbgprintf("action %d\n", val[0]);

      process(c, val, length);

    }

  public:
    ServerCharCallbacks() {
      buff = new unsigned char[1024];
    }
    ~ServerCharCallbacks() {
      delete[] buff;
    }

};

void server_setup() {
  char buff[4];
  unsigned char r;

  random32((unsigned char*)&r, 1);
  r %= 100;

  itoa(r, buff, 16);

  BLEDevice::init(std::string("srv") + buff);
  BLEServer *pServer = BLEDevice::createServer();
  pServer->setCallbacks(new ServerCallbacks());

  Serial.println(("Address " + BLEDevice::getAddress().toString()).c_str());

  BLEService *pService = pServer->createService(SERVER_SERVICE_UUID);
  ServerCharacteristic* pCharacteristic = new ServerCharacteristic(SERVER_CHARACTERISTIC_UUID,
      BLECharacteristic::PROPERTY_READ |
      BLECharacteristic::PROPERTY_WRITE );

  pService->addCharacteristic(pCharacteristic);
  pCharacteristic->setCallbacks(new ServerCharCallbacks());

  pService->start();
  BLEAdvertising *pAdvertising = pServer->getAdvertising();
  pAdvertising->addServiceUUID(pService->getUUID());
  pAdvertising->start();
}
