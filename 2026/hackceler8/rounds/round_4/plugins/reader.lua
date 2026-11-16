local c = require('common')

function new(ctrl)
  local r = {
    controller = ctrl,
    low_bits = 0,
    high_bits = 0,
    prev_low_bits = 0,
    prev_high_bits = 0,
    ready = false,
    changed = false,
  }

  function r.on_write(self, address, data, mask)
    return self.controller:on_write(address, data, mask)
  end

  function r.keys(self)
    return c.from_bits(self.high_bits, self.low_bits)
  end

  function r.on_read(self, address, data, mask)
    self.ready = false
    self.changed = false

    self.controller:on_read(address, data, mask, function(current_state, input)
      if current_state == State.DoReadHigh then
        self.high_bits = input
      elseif current_state == State.DoReadLow then
        self.low_bits = input
        self.ready = true
        if self.prev_high_bits ~= self.high_bits or self.prev_low_bits ~= self.low_bits then
          self.changed = true
        end
        self.prev_high_bits = self.high_bits
        self.prev_low_bits = self.low_bits
      end
    end)
  end

  return r
end

return {
  new = new
}
