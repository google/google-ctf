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



#include <cstdio>
#include "common.h"

bool SendPacket(NetSock *s, const Packet *p) {
  int ret = s->WriteAll(p->type.c_str(), 4);
  if (ret != 4) {
    return false;
  }

  uint32_t data_sz = p->data.size();
  ret = s->WriteAll(&data_sz, sizeof(data_sz));
  if (ret != sizeof(data_sz)) {
    return false;
  }

  ret = s->WriteAll(&p->data[0], data_sz);
  if (ret != (int)data_sz) {
    return false;
  }

  return true;
}

bool RecvPacket(NetSock *s, Packet *p) {
  char type[5]{};
  uint32_t data_sz;

  int ret = s->ReadAll(type, 4);
  if (ret != 4) {
#ifdef DEBUGCLIENT
    puts("RecvPacket: type recv"); fflush(stdout);
#endif
    return false;
  }

  ret = s->ReadAll(&data_sz, sizeof(data_sz));
  if (ret != sizeof(data_sz)) {
#ifdef DEBUGCLIENT
    puts("RecvPacket: size recv"); fflush(stdout);
#endif
    return false;
  }

  if (data_sz > 256 * 1024 /* 256 KB */) {
#ifdef DEBUGCLIENT
    printf("RecvPacket: data size bad: %x", data_sz); fflush(stdout);
#endif
    return false;
  }

  p->type = type;
  p->data.resize(data_sz);

  ret = s->ReadAll(&p->data[0], data_sz);
  if (ret != (int)data_sz) {
#ifdef DEBUGCLIENT
    puts("RecvPacket: data recv"); fflush(stdout);
#endif
    return false;
  }

  return true;
}

bool SendText(NetSock *s, const char *t) {
  size_t sz = strlen(t);

  Packet p;
  p.type = "TEXT";
  p.data.resize(sz);
  memcpy(&p.data[0], t, sz);

  return SendPacket(s, &p);
}

bool SendMap(NetSock *s, uint8_t *game_map) {
  const size_t data_sz = (MAP_W * (MAP_H + 1)) / 8;
  Packet p;
  p.type = "GMAP";
  p.data.resize(data_sz);
  memcpy(&p.data[0], game_map, data_sz);

  return SendPacket(s, &p);
}


bool SendTankData(NetSock *s, Tank tanks[2]) {
  Packet p;
  p.type = "TANK";
  p.data.resize(sizeof(Tank) * 2);
  memcpy(&p.data[0 * sizeof(Tank)], &tanks[0], sizeof(Tank));
  memcpy(&p.data[1 * sizeof(Tank)], &tanks[1], sizeof(Tank));

  return SendPacket(s, &p);
}

bool SendTargetingData(NetSock *s, TargetingData *t) {
  Packet p;
  p.type = "FIRE";
  p.data.resize(sizeof(TargetingData));
  memcpy(&p.data[0], t, sizeof(TargetingData));

  return SendPacket(s, &p);
}

bool SendBulletEvent(NetSock *s, const std::vector<BulletEvent>& bullet_ev) {
  Packet p;
  p.type = "BLLT";
  p.data.resize(sizeof(BulletEvent) * bullet_ev.size());
  memcpy(&p.data[0], &bullet_ev[0],
      sizeof(BulletEvent) * bullet_ev.size());

  return SendPacket(s, &p);
}


