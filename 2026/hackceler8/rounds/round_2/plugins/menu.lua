local trace_lookup = {
  [2] = 'a',
  [3] = 'b',
  [4] = 'c'
}

function new(name, user_callback)
  local m = {
    selection = 2,
    name = name,
    user_callback = user_callback,
  }

  function m.mark(self, row)
    if self.selection == row then
      return "x"
    else
      return " "
    end
  end

  function m.populate(self)
    return {
      { "Select next slot", "",           "heading" },
      { "Slot A",           self:mark(2), "" },
      { "Slot B",           self:mark(3), "" },
      { "Slot C",           self:mark(4), "" } }
  end

  function m.callback(self, index, event)
    -- Select the current option
    if event == "select" then
      self.selection = index
      return true -- returning true indicates that the menu needs a refresh
    -- Player pressed ESC or selected the close menu option.
    elseif event == "back" or (index == 0 and event == "13") then
      self.user_callback(trace_lookup[self.selection])
      emu.unpause()
      return false
    end

    -- Otherwise do nothing
    return false
  end

  function m.show(self)
    emu.pause()
    emu.show_menu(self.name)
  end

  emu.register_menu(
    function(index, event) return m:callback(index, event) end,
    function() return m:populate() end,
    m.name)
  return m
end

return {
  new = new
}
