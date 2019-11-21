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
// This file contains your configuration used to connect to Cloud IoT Core

// Cloud iot details.
const char *project_id = "SNIP";
const char *location = "SNIP";
const char *registry_id = "SNIP";
const char *device_id = "SNIP";

// Configuration for NTP
const char* ntp_primary = "pool.ntp.org";
const char* ntp_secondary = "time.nist.gov";

// To get the private key run (where private-key.pem is the ec private key
// used to create the certificate uploaded to google cloud iot):
// openssl ec -in <private-key.pem> -noout -text
// and copy priv: part.
// The key length should be exactly the same as the key length bellow (32 pairs
// of hex digits). If it's bigger and it starts with "00:" delete the "00:". If
// it's smaller add "00:" to the start. If it's too big or too small something
// is probably wrong with your key.
const char *private_key_str = "SNIP";


// Time (seconds) to expire token += 20 minutes for drift
const int jwt_exp_secs = 3600; // Maximum 24H (3600*24)

// To get the certificate for your region run:
//   openssl s_client -showcerts -connect mqtt.googleapis.com:8883
// for standard mqtt or for LTS:
//   openssl s_client -showcerts -connect mqtt.2030.ltsapis.goog:8883
// Copy the certificate (all lines between and including ---BEGIN CERTIFICATE---
// and --END CERTIFICATE--) to root.cert and put here on the root_cert variable.

const char *root_cert =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIErjCCA5agAwIBAgIQW+5sTJWKajts11BgHkBRwjANBgkqhkiG9w0BAQsFADBU\n"
    "MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVR29vZ2xlIFRydXN0IFNlcnZpY2VzMSUw\n"
    "IwYDVQQDExxHb29nbGUgSW50ZXJuZXQgQXV0aG9yaXR5IEczMB4XDTE5MDYxMTEy\n"
    "MzE1OVoXDTE5MDkwMzEyMjAwMFowbTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNh\n"
    "bGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxEzARBgNVBAoMCkdvb2ds\n"
    "ZSBMTEMxHDAaBgNVBAMME21xdHQuZ29vZ2xlYXBpcy5jb20wggEiMA0GCSqGSIb3\n"
    "DQEBAQUAA4IBDwAwggEKAoIBAQDHuQUoDZWl2155WvaQ9AmhTRNC+mHassokdQK7\n"
    "NxkZVZfrS8EhRkZop6SJGHdvozBP3Ko3g1MgGIZFzqb5fRohkRKB6mteHHi/W7Uo\n"
    "7d8+wuTTz3llUZ2gHF/hrXFJfztwnaZub/KB+fXwSqWgMyo1EBme4ULV0rQZGFu6\n"
    "7U38HK+mFRbeJkh1SDOureI2dxkC4ACGiqWfX/vSyzpZkWGRuxK2F5cnBHqRbcKs\n"
    "OfmYyUuxZjGah+fC5ePgDbAntLUuYNppkdgT8yt/13ae/V7+rRhKOZC4q76HBEaQ\n"
    "4Wn5UC+ShVaAGuo7BtfoIFSyZi8/DU2eTQcHWewIXU6V5InhAgMBAAGjggFhMIIB\n"
    "XTATBgNVHSUEDDAKBggrBgEFBQcDATA4BgNVHREEMTAvghNtcXR0Lmdvb2dsZWFw\n"
    "aXMuY29tghhtcXR0LW10bHMuZ29vZ2xlYXBpcy5jb20waAYIKwYBBQUHAQEEXDBa\n"
    "MC0GCCsGAQUFBzAChiFodHRwOi8vcGtpLmdvb2cvZ3NyMi9HVFNHSUFHMy5jcnQw\n"
    "KQYIKwYBBQUHMAGGHWh0dHA6Ly9vY3NwLnBraS5nb29nL0dUU0dJQUczMB0GA1Ud\n"
    "DgQWBBSKWpFfG/yH1dkkJT05y/ZnRm/M4DAMBgNVHRMBAf8EAjAAMB8GA1UdIwQY\n"
    "MBaAFHfCuFCaZ3Z2sS3ChtCDoH6mfrpLMCEGA1UdIAQaMBgwDAYKKwYBBAHWeQIF\n"
    "AzAIBgZngQwBAgIwMQYDVR0fBCowKDAmoCSgIoYgaHR0cDovL2NybC5wa2kuZ29v\n"
    "Zy9HVFNHSUFHMy5jcmwwDQYJKoZIhvcNAQELBQADggEBAKMoXHxmLI1oKnraV0tL\n"
    "NzznlVnle4ljS/pqNI8LUM4/5QqD3qGqnI4fBxX1l+WByCitbTiNvL2KRNi9xau5\n"
    "oqvsuSVkjRQxky2eesjkdrp+rrxTwFhQ6NAbUeZgUV0zfm5XZE76kInbcukwXxAx\n"
    "lneyQy2git0voUWTK4mipfCU946rcK3+ArcanV7EDSXbRxfjBSRBD6K+XGUhIPHW\n"
    "brk0v1wzED1RFEHTdzLAecU50Xwic6IniM3B9URfSOmjlBRebg2sEVQavMHbzURg\n"
    "94aDC+EkNlHh3pOmQ/V89MBiF1xDHbZZ1gB0GszYKPHec9omSwQ5HbIDV3uf3/DQ\n"
    "his=\n"
    "-----END CERTIFICATE-----\n";
