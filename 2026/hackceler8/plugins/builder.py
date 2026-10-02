import struct
import enum


@enum.unique
class Buttons(enum.IntEnum):
    """Controller buttons mapped to their bitmask values."""

    NONE = 0
    B = 1 << 0
    C = 1 << 1
    DOWN = 1 << 2
    LEFT = 1 << 3
    RIGHT = 1 << 4
    UP = 1 << 5
    A = 1 << 6
    START = 1 << 7


@enum.unique
class TraceFlags(enum.Enum):
    """Flags that the replayer applies to the trace."""

    # Starts the replay of the trace immediately.
    REPLAY_IMMEDIATELY = 0
    # Waits for the reset before replying the trace.
    WAIT_FOR_RESET = 1


class Frame:
    """Single "frame" of the replay."""

    def __init__(self, frame, buttons=Buttons.NONE):
        self.frame = frame
        self.buttons = buttons

    def build(self):
        return struct.pack("<II", self.frame, self.buttons)


class Trace:
    """Sequence of frames to replay by the replayer."""

    def __init__(self, frames, flags=TraceFlags.REPLAY_IMMEDIATELY):
        self.flags = flags
        self.frames = frames

    def __len__(self):
        return len(self.frames)

    def build(self):
        return struct.pack("<BI", self.flags.value, len(self.frames)) + b"".join(
            f.build() for f in self.frames
        )


class Replay(Trace):
    """Builds a trace based on the recording from the mame plugin."""

    def __init__(self, path, flags=TraceFlags.REPLAY_IMMEDIATELY):
        with open(path, "rb") as f:
            data = f.read()
        frames = []
        while data:
            frames.append(Frame(*struct.unpack("<II", data[:8])))
            data = data[8:]

        super().__init__(frames, flags)


class Empty(Trace):
    """Empty trace that contains no inputs."""

    def __init__(self):
        super().__init__([])


class Stage:
    """A stage of replay contains 3 possible replay slots that are selectable by buttons."""

    def __init__(self, a=None, b=None, c=None):
        self.a = a if a is not None else Empty()
        self.b = b if b is not None else Empty()
        self.c = c if c is not None else Empty()

    def build(self):
        return self.a.build() + self.b.build() + self.c.build()


class File:
    """Replay file is a sequence of replay stages."""

    def __init__(self, stages):
        if not stages:
            raise ValueError("Stages must not be empty.")
        self.stages = stages

    def build(self):
        return struct.pack("<B", len(self.stages)) + b"".join(
            s.build() for s in self.stages
        )
