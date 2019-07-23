/**
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import com.sun.jna.Library;
import com.sun.jna.Native;

import java.util.*;
import java.util.function.Function;

public class FancyJIT {
    public interface CompilierLib extends Library {
        CompilierLib INSTANCE = Native.load("compiler", CompilierLib.class);

        int run(String[] program, int proglen);
    }

    static class Instr {
        String name;
        char reg;
        int arg;

        Instr(String name, char reg, int arg) {
            this.name = name;
            this.reg = reg;
            this.arg = arg;
        }
    }

    static class Parser {
        static HashMap<String, Function<String, Optional<Instr>>> parsers = new HashMap<>();
        static Function<String, Optional<Instr>> parse2Arg = (String cmd) -> {
            if (cmd.charAt(4) != 'A' && cmd.charAt(4) != 'B') {
                return Optional.empty();
            }
            if (cmd.charAt(5) != ',' || cmd.charAt(6) != ' ') {
                return Optional.empty();
            }
            return Optional.of(new Instr(
                    cmd.substring(0, 3),
                    cmd.charAt(4),
                    Integer.parseInt(cmd.substring(7, cmd.length() - 1))));
        };
        static Function<String, Optional<Instr>> parse1Arg = (String cmd) -> {
            return Optional.of(new Instr(
                    cmd.substring(0, 3),
                    'X',
                    Integer.parseInt(cmd.substring(4, cmd.length() - 1))));
        };
        static Function<String, Optional<Instr>> parse0Arg = (String cmd) -> {
            if (cmd.length() != 5) {
                return Optional.empty();
            }
            return Optional.of(new Instr(cmd.substring(0, 3), 'X', 0));
        };
        static {
            parsers.put("MOV", parse2Arg);
            parsers.put("ADD", parse2Arg);
            parsers.put("SUB", parse2Arg);
            parsers.put("CMP", parse2Arg);
            parsers.put("LDR", parse2Arg);
            parsers.put("STR", parse2Arg);
            parsers.put("JMP", parse1Arg);
            parsers.put("JNE", parse1Arg);
            parsers.put("JEQ", parse1Arg);
            parsers.put("SUM", parse0Arg);
            parsers.put("RET", parse0Arg);
        }

        static Optional<Instr> parse(String cmd) {
            if (cmd.length() < 5) {
                return Optional.empty();
            }
            if (cmd.charAt(3) != '(' || cmd.charAt(cmd.length() - 1) != ')') {
                return Optional.empty();
            }
            return parsers.getOrDefault(cmd.substring(0, 3), x -> Optional.empty()).apply(cmd);
        }
    }

    private static boolean validate(String[] program) {
        if (program.length > 800) {
            return false;
        }
        for (int i = 0; i < program.length; i++) {
            String cmd = program[i];
            Optional<Instr> oinstr = Parser.parse(cmd);
            if (!oinstr.isPresent()) {
                return false;
            }
            Instr instr = oinstr.get();
            switch (instr.name) {
                case "MOV":
                    if (instr.arg < 0 || instr.arg > 99999) {
                        return false;
                    }
                    break;
                case "ADD":
                case "SUB":
                case "CMP":
                    if (instr.arg < 0 || instr.arg > 99999 || instr.reg != 'A') {
                        return false;
                    }
                    break;
                case "LDR":
                case "STR":
                    if (instr.arg < 0 || instr.arg > 30) {
                        return false;
                    }
                    break;
                case "JMP":
                case "JNE":
                case "JEQ":
                    if (instr.arg < 0 || instr.arg >= program.length || Math.abs(i - instr.arg) > 20) {
                        return false;
                    }
                    break;
                case "SUM":
                case "RET":
                    break;
                default:
                    return false;
            }
        }
        return true;
    }

    public static void main(String[] args) {
        System.out.println("Please enter your program. We'll JIT-compile it, run, and show you the result:");
        Scanner scanner = new Scanner(System.in);
        ArrayList<String> prog = new ArrayList<>();
        while (true) {
            String line = scanner.nextLine();
            if (line.isEmpty()) {
                break;
            }
            prog.add(line);
        }
        // System.err.println(prog);
        String[] progArr = prog.toArray(new String[0]);
        if (!validate(progArr)) {
            System.out.println("Sorry, your program has some errors.");
        } else {
            int res = CompilierLib.INSTANCE.run(progArr, progArr.length);
            System.out.println("Here is your computation result: " + res);
        }
    }
}
