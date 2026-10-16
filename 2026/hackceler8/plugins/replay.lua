local c = require('common')

local cpu = manager.machine.devices[":maincpu"]
local mem = cpu.spaces["program"]

local function new(w, next_frame_callback, end_callback)
  local next_frame, next_keys = next_frame_callback()
  local r = {
    w = w,
    next_frame_callback = next_frame_callback,
    end_callback = end_callback,
    frame = 0,
    next_frame = next_frame,
    next_keys = next_keys,
    read_tap = nil,
    write_tap = nil
  }

  function r.advance(self)
    self.next_frame, self.next_keys = next_frame_callback()
    self.frame = -1
  end

  function r.handle_write(self, address, data, mask)
    self.w:on_write(address, data, mask)
  end

  function r.handle_read(self, address, data, mask)
    if self.next_frame == nil then
      self.end_callback()
      return nil
    end

    if self.frame == self.next_frame then
      io.write(string.format('frame=%d down=%s up=%s left=%s right=%s start=%s a=%s b=%s c=%s\n',
        self.next_frame, self.next_keys.down, self.next_keys.up, self.next_keys.left, self.next_keys.right,
        self.next_keys.start, self.next_keys.a,
        self.next_keys.b, self.next_keys.c))
      self.w:set_keys(self.next_keys)
      self.next_frame, self.next_keys = self.next_frame_callback()
      if self.next_frame == nil then
        self.end_callback()
        return nil
      end
    end
    local value = self.w:on_read(address, data, mask)
    if self.w.ready then
      self.frame = self.frame + 1
    end
    return value
  end

  function r.bind(self)
    self.read_tap = mem:install_read_tap(c.IO_BASE_START, c.IO_BASE_END, "replay read",
      function(address, data, mask) return self:handle_read(address, data, mask) end)
    self.write_tap = mem:install_write_tap(c.IO_BASE_START, c.IO_BASE_END, "replay write",
      function(address, data, mask) return self:handle_write(address, data, mask) end)
  end

  function r.unbind(self)
    --- @diagnostic disable-next-line: undefined-field
    self.read_tap:remove()
    self.read_tap = nil
    ---@diagnostic disable-next-line: undefined-field
    self.write_tap:remove()
    self.write_tap = nil
  end

  return r
end

return {
  new = new
}
