local c = require('common')

local cpu = manager.machine.devices[":maincpu"]
local mem = cpu.spaces["program"]

local on_exit = emu.register_stop
if emu['add_machine_stop_notifier'] ~= nil then
  on_exit = emu.add_machine_stop_notifier
end

local function new(r, sink, end_callback)
  local m = {
    r = r,
    sink = sink,
    end_callback = end_callback,
    read_tap = nil,
    write_tap = nil,
    end_tap = nil,
    frame = 0
  }

  function m.reset_counter(self)
    self.frame = 0
  end

  function m.handle_write(self, address, data, mask)
    self.r:on_write(address, data, mask)
  end

  function m.handle_read(self, address, data, mask)
    self.r:on_read(address, data, mask)
    if self.r.changed then
      self.sink(self.frame, self.r:keys())
    end
    if r.ready then
      self.frame = self.frame + 1
    end
  end

  function m.start_from(self, other)
    self.frame = other.frame
  end

  function m.bind(self)
    self.read_tap = mem:install_read_tap(c.IO_BASE_START, c.IO_BASE_END, "record read",
      function(address, data, mask) return self:handle_read(address, data, mask) end)
    self.write_tap = mem:install_write_tap(c.IO_BASE_START, c.IO_BASE_END, "record write",
      function(address, data, mask) return self:handle_write(address, data, mask) end)
    self.end_tap = on_exit(function() self.end_callback(self.frame) end)
  end

  function m.unbind(self)
    ---@diagnostic disable-next-line: undefined-field
    self.read_tap:remove()
    self.read_tap = nil
    ---@diagnostic disable-next-line: undefined-field
    self.write_tap:remove()
    self.write_tap = nil
    ---@diagnostic disable-next-line: undefined-field
    self.end_tap:remove()
    self.end_tap = nil
  end

  return m
end

return {
  new = new
}
