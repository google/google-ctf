JPEG divides image data in 8x8 blocks that are transformed using a Discrete
Cosine Transform. Thus, image data in every JPEG file is present up to side
lengths that are a multiple of 8.

When encoding a non-grayscale JPEG, JPEG supports subsampling some of the
channels. This is typically used to achieve "chroma subsampling", a process in
which the chromaticity channels are saved (for example) at half resolution.
This is encoded in the file as "sampling factors", and for example sampling
factors of "2x2,1x1,1x1" correspond to half the horizontal/vertical resolution
for chroma channels than for the luma channel.

In case subsampling is used, the minimum unit of pixel data present changes from
8x8 to "8x8 for an hypothetical channel with factors 1x1". So, for a
"2x2,1x1,1x1" JPEG, pixel data is padded to multiples of 16x16.

The JPEG file provided for this challenge has sampling factors "3x1,3x1,3x1",
hence the pixel data is padded to multiples of 24x8. 512 is not a multiple of
24, but 528 is; opening the JPEG file with an hex editor and changing image
width to 528 recovers the flag.
