-- $A1001A 	$A1001B 	Expansion port serial transmit
-- $A1001C 	$A1001D 	Expansion port serial receive
-- $A1001E 	$A1001F 	Expansion port serial control
function get_memory()
    return manager.machine.devices[":maincpu"].spaces["program"]
end

function callback(offset, data, mask)
    io.write(string.char(data >> 8))
end

function run()
    get_memory():install_write_tap(0xA1001A, 0xA1001B, "console device tx", callback)
end

run()
