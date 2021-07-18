# Polymorph

You have many samples of the same malware, but it changes every time. Write an antivirus program that can discern between malicious and legitimate.

You can find the malware samples in the `malware` directory. **The "malware" is not actually malicious and will not harm your computer. Instead, it will simply display the [EICAR test file](https://secure.eicar.org/eicar.com.txt).**

## Your Antivirus Program

Your antivirus program must take a single command-line argument: the path to an executable file. It must `exit(0)` if the file is not malicious, or `exit(nonzero)` if the file is malicious. (Specifically, if it is a sample of the Polymorph malware). It must, on average, take less than 4 seconds to run per sample.

## The Autograder

You will submit your program to the Autograder to be judged. The Autograder will execute your program on two sets of binaries:
 - The provided public "safe" and "malware" binaries
 - A secret set of "safe" and "malware" binaries

Your program must be entirely accurate on the provided binaries, but is allowed to be slightly incorrect on the secret set. If the Autograder judges your program worthy, it shall present you with the flag.

To submit to the autograder, first send a newline-terminated solution to the proof-of-work challenge, followed by 4 little-endian bytes specifying the size of your antivirus file, followed by said antivirus file. You may use the provided `upload_for_scoring.py` to do this for you. Usage is `./upload_for_scoring.py <your-antivirus> <host> <port>`.

## Debugging

You will be permitted to see the stderr and stdout of your binary when running on the public test cases. Be sure to test your detection techniques on the autograder before developing them too much - some operations may be disallowed in the sandboxed environment.
