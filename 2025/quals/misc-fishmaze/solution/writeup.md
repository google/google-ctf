# FishMaze
The challenge tells you to get out of the maze. There is a input section to fill out a "player kernel". If you look at the source of the page you see this hidden blob:

```
    <div style="display:none;">
        Note to our intern: make Sure to remove these notes so players don't see it!

        mapdata.shape is (8,)
        It has ASCII codes of:
        A0 A1 A2
        A3 * A4
        A5 A6 A7
        Where "#" is wall, " " is open, "R" is ray, "F" is falcon

        output.shape is (1 + 64,)
        aux.shape is (64,)
        OUTPUT ACTIONS:
        0 : stay still
        1 : move left
        2 : move right
        3 : move up
        4 : move down
        Put your action in output[0]
        After each turn:OUTPUT[1:] gets copied into AUX_DATA so you can use aux as memory/scratch
    </div>
```

Which describes the IO of the kernel: you get the 8 neighbouring location and an auxillary scratch buffer, and you are supposed to put your action in output[0]. The maze is static and you always start at same location which makes this very easy: you can just statically hardcode your way out. Also, the enemies are a misdirection: once you run the game you realize they barely spawn, which is good, because given a line of sight of 1 cell there is not much you can do to evade them.

There are many ways to write the kernel, one is to just setup your movement as phases of 2: in each phase you cycle through (Action1, Action2) for a given number of steps. So each phase takes 3 fields: (N, A1, A2) meaning you do {A1, A2, A1, ..} until N steps then move to next phase. You can even make a kernel to navigate in a map-agnostic way by doing a maze search algo but that's not needed here.

The multiple 2 action phases solution:
```
def player_kernel(mapdata_ref, auxdata_ref, out_ref):
    phase = auxdata_ref[0]
    step = auxdata_ref[1]
    @pl.when(phase == 0)
    def _():
        out_ref.at[1].set(1)
        out_ref.at[2].set(0)
    xstart = 3
    out_ref.at[xstart + 0].set(16) 
    out_ref.at[xstart + 1].set(1)
    out_ref.at[xstart + 2].set(4)
    out_ref.at[xstart + 3].set(32)
    out_ref.at[xstart + 4].set(1)
    out_ref.at[xstart + 5].set(3)
    out_ref.at[xstart + 6].set(80)
    out_ref.at[xstart + 7].set(2)
    out_ref.at[xstart + 8].set(3)
    act = auxdata_ref[3 * phase + (step % 2)]
    is_maxstep = (step + 1) > auxdata_ref[3*phase - 1]
    phase = lax.cond(is_maxstep, lambda x, _: x, lambda _, y: y, phase + 1, phase)
    step = lax.cond(is_maxstep, lambda x, _: x, lambda _, y: y, 0, step + 1)
    out_ref.at[1].set(phase)
    out_ref.at[2].set(step)
    out_ref.at[0].set(act)
```

Once you run this and your fish gets off the map the page shows you the flag. CTF{1r0nw00d_h43_4ll_tH3_fl0pS_ar3_y0u_r3AdY4aGi}, IronWood is the latest generation of TPUs, the accelerators that power Gemini and AlphaFold and you can program them with these kernels. 

* Learn more about TPUs: g.co/tpu. 

* Learn more about Pallas kernels: https://docs.jax.dev/en/latest/pallas/index.html (it can also run on GPUs). 

P.S. The quote by Dan Dennet on top is from "Freedom Evolves" where he discusses cellular automata and how deterministic systems allow for agency: i.e. you can predict and dodge a glider from Game Of Life. In this case, they rays and falcons moved deterministically, at higher line of sight you could use that determinism survive a lot of them.
