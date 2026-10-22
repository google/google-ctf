local function enum(values)
  local t = {}
  for _, v in ipairs(values) do
    t[v] = v
  end
  return t
end

State = enum {
  "Uninitialized",
  "PrepareReadHigh",
  "DoReadHigh",
  "PrepareReadLow",
  "DoReadLow",
}

function new(data_addr, control_addr)
  local c = {
    current_state = State.Uninitialized,
  }

  function c.on_write(self, address, data, mask)
    if self.current_state == State.Uninitialized then
      if address == control_addr and (data & mask) == 0x40 then
        self.current_state = State.PrepareReadHigh
      end
    elseif self.current_state == State.PrepareReadHigh then
      if address == data_addr and (data & mask) == 0x40 then
        self.current_state = State.DoReadHigh
      end
    elseif self.current_state == State.PrepareReadLow then
      if address == data_addr and (data & mask) == 0 then
        self.current_state = State.DoReadLow
      end
    end
  end

  function c.on_read(self, address, data, mask, callback)
    local retval = nil
    if self.current_state == State.DoReadHigh then
      if address == data_addr then
        retval = callback(self.current_state, data & mask)
        self.current_state = State.PrepareReadLow
      end
    elseif self.current_state == State.DoReadLow then
      if address == data_addr then
        retval = callback(self.current_state, data & mask)
        self.current_state = State.PrepareReadHigh
      end
    end

    return retval
  end

  return c
end

return {
  new = new,
  State = State,
}
