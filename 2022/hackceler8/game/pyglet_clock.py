import pyglet
import time

from heapq import heappop as _heappop
from heapq import heappush as _heappush
from heapq import heappushpop as _heappushpop

MAX_LAG_RECOVERY = 1.0

class Clock(pyglet.clock.Clock):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.priority_list = {}

    def call_scheduled_functions(self, dt):
        """Call scheduled functions that elapsed on the last `update_time`.

        Modified from the default implementation to allow scheduling "in the
        past", causing subsequent frames to run immediately if we are running
        behind. Allows marking particular functions to have a certain amount of
        "priority", which causes it to run multiple times in a row to catch up
        even if that prevents others from running, up to some limit.

        .. versionadded:: 1.2

        :Parameters:
            dt : float
                The elapsed time since the last update to pass to each
                scheduled function.  This is *not* used to calculate which
                functions have elapsed.

        :rtype: bool
        :return: True if any functions were called, otherwise False.
        """
        now = self.last_ts
        result = False  # flag indicates if any function was called

        # handle items scheduled for every tick
        if self._schedule_items:
            result = True
            # duplicate list in case event unschedules itself
            for item in list(self._schedule_items):
                item.func(dt, *item.args, **item.kwargs)

        # check the next scheduled item that is not called each tick
        # if it is scheduled in the future, then exit
        interval_items = self._schedule_interval_items
        try:
            if interval_items[0].next_ts > now:
                return result

        # raised when the interval_items list is empty
        except IndexError:
            return result

        # NOTE: there is no special handling required to manage things
        #       that are scheduled during this loop, due to the heap
        self._current_interval_item = item = None
        get_soft_next_ts = self._get_soft_next_ts
        to_schedule = []
        while interval_items:
            item = _heappop(interval_items)

            # a scheduled function may try and unschedule itself
            # so we need to keep a reference to the current
            # item no longer on heap to be able to check
            self._current_interval_item = item

            # if next item is scheduled in the future then break
            if item.next_ts > now:
                _heappush(interval_items, item)
                break

            for i in range(self.get_priority(item.func)):
                # execute the callback
                try:
                    item.func(item.interval, *item.args, **item.kwargs)
                except ReferenceError:
                    pass    # weakly-referenced object no longer exists.

                if item.interval:
                    item.next_ts += item.interval
                    item.last_ts += item.interval

                    if now - item.last_ts > MAX_LAG_RECOVERY:
                        # Cap the amount we can be behind schedule.
                        item.last_ts = now - MAX_LAG_RECOVERY
                        item.next_ts = item.last_ts + item.interval
                    if now < item.next_ts:
                        break

                else:
                    # not an interval, so this item will not be rescheduled
                    self._current_interval_item = item = None
                    break

            if item is not None and item.interval:
                to_schedule.append(item)

        for item in to_schedule:
            _heappush(interval_items, item)

        return True

    def reset_timers(self):
        now = self.time()
        new_heap = []
        for item in self._schedule_interval_items:
            item.last_ts = now
            item.next_ts = now + item.interval
            _heappush(new_heap, item)
        self._schedule_interval_items = new_heap

    def mark_priority(self, func, max_consecutive):
        """Indicate that func is allowed to run max_consecutive times in a row, at the expense of other funcs."""
        self.priority_list[func] = max_consecutive

    def get_priority(self, func):
        return self.priority_list.get(func, 1)

class FpsCounter:
    def __init__(self, clock, reset_period=float('inf')):
        self.clock = clock
        self.reset_period = reset_period
        self.start_time = self.clock.time()
        self.frames = 0
        self.last_reset_fps = None

    def fps(self):
        if self.last_reset_fps != None:
            return self.last_reset_fps
        return self._fps()

    def _fps(self):
        return self.frames / (self.clock.last_ts - self.start_time)

    def tick(self):
        self.frames += 1
        if self.clock.last_ts - self.start_time > self.reset_period:
            self.last_reset_fps = self._fps()
            self.start_time += self.reset_period
            self.frames = 0

