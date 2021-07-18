# Autorunner

We at DevMaster Technologies are always innovating in the area of terrible code execution services. Remember AutoRun? We've brought it back! But this time with Security™.

Our new autorun works on ZIP files. Include a file ending in `.autorun.py`, and when we unzip the zip file, we'll run it for you. However, your script must have a proprietary DevMaster Signature™.

In this alpha release, we've provided a valid ZIP file that you can try out. This is because our engineers are out for the weekend celebrating the launch, and won't be signing new files any time soon. Only a human can make sure you don't read the `/home/user/flag` file, after all. Sandboxing tools that would prevent that definitely don't exist.

Of course, we unzip the file with our new, proprietary, ultra-speedy `turbozipfile` extension. It's a drop-in replacement for `zipfile` (read-only).

# Running the challenge

You can test locally with `python3 ./autorunner.py ./zipfile.zip ./unzip_dir`. 

You can run remotely with `./send_zip.py ./zipfile.zip <host> <port>`. We'll unzip the file for you, and if there's a signed and valid `.autorun.py`, we'll run it. The server uses Python 3.8.

# Some tips

We strongly recommend Python 3.8+. We've provided `turbozipfile` as a compiled module for python 3.8, as well as the C source. You can compile for a different Python version with `python3 ./setup.py build`; however, this is not required. This challenge does not require native coverage or sanitizers in order to be solved.

Atheris is still in active development, and we recently released significant improvements. These change how Python coverage works, so be sure to read the right documentation for the version you're using: [new](https://github.com/google/atheris/) vs [old](https://github.com/google/atheris/tree/1.0). Both versions work for this challenge.
