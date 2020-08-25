# Android Ads

## Overview

The app has a username and password field and a WebView that displays an
attacker provided ad. The goal is to escape the WebView and exfiltrate the
contents of the password text field.

The intended exploit is a combination of a path traversal bug and a JAR
signature verification bypass using
[Janus](https://blog.trendmicro.com/trendlabs-security-intelligence/janus-android-app-signature-bypass-allows-attackers-modify-legitimate-apps/).

## Directories

- `app/` - Source code for the Android app and exploit.
- `app/janusify` - Python script for merging a DEX file and a JAR file together.
- `app/exploit` - Example exploit Java code.

### App

#### Building

The `make-release.sh` script can be used to make the release signed APK. The
password for the keystore is `password`.

#### Running

The app has an empty username and password text fields. These can be populated
dynamically at app start to provide the flag value:

```
$ adb shell am start com.example.app/.MainActivity
$ adb shell input text 'username'
$ adb shell input keyevent KEYCODE_TAB
$ adb shell input text 'flag{someflagvalue}'
```

The app listens for the broadcast with the action `com.example.app.LOAD_AD` and
loads the URL in the WebView at the bottom of the activity.

```
$ adb shell am broadcast \
    -a 'com.example.app.LOAD_AD' \
    -d 'http://example.com/exploit.html'
```

### Exploit

There are two parts to the exploit: an HTML ad and an APK file. Both must be
hosted on an HTTP server.

An example exploit is provided in `app/exploit`. The HTML file,
`app/exploit/exploit.html` should have the embedded APK URL updated to point to
the location of the hosted APK component.

The `app/exploit/src/main/java/com/ads/sdk/impl/AdFactoryImpl.java` file needs
to be updated to point to the HTTP server address for flag exfiltration as well.

The `app/make-exploit.sh` script can be used to build the exploit APK, it should
be run from the `app/` directory.
