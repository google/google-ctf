function get_memory()
    return manager.machine.devices[":maincpu"].spaces["program"]
end

got_flag = false

while true do
    emu.wait_next_update()
    id = get_memory():read_u8(0xFF0000)
    if not got_flag and id > 0 then
        got_flag = true
        io.write("Got flag {")
        io.write(string.char(id))
        io.write("}\n")
    end
end