# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Use adafruit-ampy (https://pypi.org/project/adafruit-ampy/)
# You should already have this installed as part of your prework.
# Otherwise please let me know and we will figure it out :)
#
# To run this script:
# > ampy --port PORTNAME run filename.py
#
# Where PORTNAME is depending on your Operation System
#
# For Linux: Most likely /dev/ttyUSB$X
# For MacOS: Most likely /dev/tty.usbserial-$X
# For Windows: COM$X
# where $X: int
from machine import SoftI2C, Pin
import time

###############################################################################
# Do not change anything in this part
###############################################################################
def todo(what):
    # This function does not need to be implemented - instead make sure it is
    # never called :)
    raise Exception("TODO: Implement me :) ({})".format(what))

# See datasheet 7.4 Step 4 - CRC
def crc8(data):
    v = 0xFF
    for di in data:
        v ^= di
        for i in range(8):
            if v & 0x80:
                v <<= 1
                # Polynomial  = 1 + x^4 + x^5 + x^ 8 => 0x31
                v ^= 0x31
                v &= 0xFF
            else:
                v <<= 1
                v &= 0xFF
    return v & 0xFF

# Due to missing documentation: Adapted from
# https://github.com/RobTillaart/DHT20/blob/master/DHT20.cpp#L294
def reset_register(i2c, sensor_i2c_address, reg):
    print("Resetting register {}".format(reg))
    i2c.writeto(sensor_i2c_address, bytes([reg, 0, 0]))
    time.sleep(5)
    data = i2c.readfrom(sensor_i2c_address, 3)
    time.sleep(10)
    i2c.writeto(sensor_i2c_address, bytes([reg | 0xB0, data[1], data[2]]))
    time.sleep(5)

def check_device_status(i2c, sensor_i2c_address):
    print("Checking sensor status")
    while True:
        status = i2c.readfrom(sensor_i2c_address, 1)[0]
        print("Device status = 0x{:02X}".format(status))
        if (status & 0x18) == 0x18:
            break
        print("Device requires initialization")
        print("!!! Please let me know if that happens !!!")
        reset_register(i2c, sensor_i2c_address, 0x1B)
        reset_register(i2c, sensor_i2c_address, 0x1C)
        reset_register(i2c, sensor_i2c_address, 0x1E)

###############################################################################
# Fill in the TODOs below
###############################################################################

# TODO(you): Fill in. Check the ESP32 pinout and find WIRE_SDA/WIRE_SCL
scl = Pin(todo("scl pin number"))
sda = Pin(todo("sda pin number"))

# Configure the communication channel
i2c = SoftI2C(freq=400000, scl=scl, sda=sda)

# TODO(you): Fill in. Check Datasheet section 7.3 of the sensor
sensor_i2c_address = todo("i2c device sensor_i2c_address")

# 7.4] Step 1) Check the device is initialized
check_device_status(i2c, sensor_i2c_address)

# 7.4] Step 2) Wait for 10ms before starting the measurement
time.sleep(0.01)

# 7.4] Step 2) Start measurement
# TODO(you): Fill in. It expects 3 values:
i2c.writeto(sensor_i2c_address, bytes([
    todo("Look at the datasheet - 7.4 Step 2"),
    todo("Look at the datasheet - 7.4 Step 2"),
    todo("Look at the datasheet - 7.4 Step 2"),
]))

print("Measuring")
# 7.4] Step 3) Wait for 80ms
time.sleep(0.08)
while True:
    # Check if the device is ready or needs more time.
    status = i2c.readfrom(sensor_i2c_address, 1)[0]
    if (status & 0x80) != 0x80:
        break

    time.sleep(0.01)

print("Receiving response")
# 6 bytes of data, 1 byte of CRC
res = i2c.readfrom(sensor_i2c_address, 7)

# 7.4] Step 4) Check CRC
if crc8(res[:6]) != res[6]:
    print("CRC incorrect, data corrupt")
    raise SystemExit()

# 7.4] Step 5) Extract the values
humidity = (res[1] << 12) | (res[2] << 4) + res[3] >> 4
temperature = ((res[3] & 0x0F) << 16) | (res[4] << 8) | res[5]

# 8] Signal Conversion
humidity = 100.0 * humidity / float(pow(2, 20))
temperature = temperature / float(pow(2, 20)) * 200 - 50

print("Sensor reported: humidity={}% at {}C".format(humidity, temperature))

