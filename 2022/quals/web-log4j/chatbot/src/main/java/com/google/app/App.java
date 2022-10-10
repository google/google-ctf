/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.app;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.lang.System;
import java.time.format.DateTimeFormatter;
import java.time.LocalDateTime;
import java.util.Arrays;

public class App {
  public static Logger LOGGER = LogManager.getLogger(App.class);
  public static void main(String[]args) {
    String flag = System.getenv("FLAG");
    if (flag == null || !flag.startsWith("CTF")) {
        LOGGER.error("{}", "Contact admin");
    }
  
    LOGGER.info("msg: {}", args);
    // TODO: implement bot commands
    String cmd = System.getProperty("cmd");
    if (cmd.equals("help")) {
      doHelp();
      return;
    }
    if (!cmd.startsWith("/")) {
      System.out.println("The command should start with a /.");
      return;
    }
    doCommand(cmd.substring(1), args);
  }

  private static void doCommand(String cmd, String[] args) {
    switch(cmd) {
      case "help":
        doHelp();
        break;
      case "repeat":
        System.out.println(args[1]);
        break;
      case "time":
        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy/M/d H:m:s");
        System.out.println(dtf.format(LocalDateTime.now()));
        break;
      case "wc":
        if (args[1].isEmpty()) {
          System.out.println(0);
        } else {
          System.out.println(args[1].split(" ").length);
        }
        break;
      default:
        System.out.println("Sorry, you must be a premium member in order to run this command.");
    }
  }
  private static void doHelp() {
    System.out.println("Try some of our free commands below! \nwc\ntime\nrepeat");
  }
}
