# Symatrix

## Challenge Files

The only files that should be provided to the players are the ones within ``/challenge``.

## Description

The CIA has been tracking a group of hackers who communicate using PNG files embedded with a custom steganography algorithm. An insider spy was able to obtain the encoder, but it is not the original code. You have been tasked with reversing the encoder file and creating a decoder as soon as possible in order to read the most recent PNG file they have sent.

### Skills tested

- Reverse engineering
- Image manipulation

## Solution

To reverse engineer the encoder file, you can use the following steps:

1. Open the encoder file in a text editor.
2. Look for comments starting with encoder.py.
3. Use the grep command to find all the lines of code that are commented.
4. Remove any duplicate lines of code.
5. Save the resulting text file as a Python script.
6. Analyze the Python script to understand how the encoder works.
7. Create a decoder script that is the inverse of the encoder script.

If you look carefully the ``encoder.c`` is created by cython, which is basically a translator from python to C.

By using the grep command we can isolate the original python code.

```cat encoder.c | grep '# <<<<<<<<<<<<<<'```

We can now analyze the python code to craft a decoder script.

The decoder script should iterate over the pixels in the image and compare them to the corresponding pixels in the mirrored image. If the pixels are different, then the decoder script should store the difference in a binary string. Once the decoder script has finished iterating over all of the pixels, it should return the binary string.

Please refer to the [solution](./solution/decoder.py) for more details.