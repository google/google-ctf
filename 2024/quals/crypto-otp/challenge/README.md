


pictures taken (edited) from `https://en.wikipedia.org/wiki/Nature_photography`


to solve:

```
mkdir recovered
python3 solvenp_preprocess-working.py tiles_encr64/ recovered/ # will take a few hours, but can be optimized (or stopped early)
mkdir flipped
for i in `ls recovered`; do convert recovered/$i -flip -rotate 270 flipped/$i; done
```



Flag: `CTF{i_th0ught_OTP_w4s_s3cure}`
