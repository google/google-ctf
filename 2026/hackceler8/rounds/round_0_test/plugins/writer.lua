local c = require('common')

function new(ctrl)
  local r = {
    controller = ctrl,
    low_bits = 0,
    high_bits = 0,
    ready = false,
  }

  function r.on_write(self, address, data, mask)
    return self.controller:on_write(address, data, mask)
  end

  function r.set_keys(self, keys)
    self.high_bits, self.low_bits = c.to_bits(keys)
  end

  function r.on_read(self, address, data, mask)
    self.ready = false

    ---@diagnostic disable-next-line: unused-local
    return self.controller:on_read(address, data, mask, function(current_state, input)
      if current_state == State.DoReadHigh then
        return self.high_bits
      elseif current_state == State.DoReadLow then
        self.ready = true
        return self.low_bits
      end
    end)
  end

  return r
end

return {
  new = new
}
