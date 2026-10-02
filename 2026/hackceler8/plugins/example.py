from builder import File, Stage, Replay

with open("replay.bin", "wb") as f:
    r = File([Stage(a=Replay("./output.mlen"))])
    f.write(r.build())
