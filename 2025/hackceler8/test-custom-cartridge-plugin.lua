-- $A1001A 	$A1001B 	Expansion port serial transmit
-- $A1001C 	$A1001D 	Expansion port serial receive
-- $A1001E 	$A1001F 	Expansion port serial control
function get_memory()
    return manager.machine.devices[":maincpu"].spaces["program"]
end

function callback(offset, data, mask)
    io.write(string.char(data >> 8))
end

-- Simulate the custom cartridge by tapping device address reads to return proper values.
function magic_value_read(offset, data, mask)
    return 1337
end

num = 0
function rng_read(offset, data, mask)
    num = num+1
    return num
end

function p3_controller_read(offset, data, mask)
    -- return ~0 -- disconnected
    return ~0x22C -- start, right
end

function p4_controller_read(offset, data, mask)
    -- return ~0 -- disconnected
    return ~0x12C -- start, left
end

state_start_iter = 0

function server_state_read(offset, data, mask)
    -- bit 0: initialized
    -- bit 1: paused
    -- bit 2..=7: team_id
    -- bit 8..=15: save_rev
    ready_state = 0x421 -- 00000100 001000 01 -> save_rev=4, team_id=8, initialized, not paused
    if state_start_iter >= 300 then
        return ready_state
    end
    state_start_iter = state_start_iter+1
    if state_start_iter < 100 then
        return 0
    elseif state_start_iter < 200 then
        return ready_state
    else
        return ready_state | 2 -- paused
    end
    return ready_state
end

function server_challenges_read(offset, data, mask)
    return 1+4+8+32+64+128+256+2048
    -- return 0
end

function lock_read(offset, data, mask)
    return 0xF012 -- Some value to bitflip
end

save_data = 0
function server_save_data_read(offset, data, mask)
    -- [0x0101, 0x0202, 0x0303, 0x0404, ...]
    save_data = (save_data + 1) % 0x100
    return save_data * 0x0101
end

-- Debug the game's writes to the custom cartridge by tapping memory writes and printing write values.
function game_state_write(offset, data, mask)
    -- print(string.format("game_state write, offs=%x, data=%x, mask=%x", offset, data, mask))
end

function game_challenges_write(offset, data, mask)
    -- print(string.format("game_challenges write, offs=%x, data=%x, mask=%x", offset, data, mask))
end

function game_save_data_write(offset, data, mask)
    -- print(string.format("game_save_data write, offs=%x, data=%x, mask=%x", offset, data, mask))
end

function lock_write(offset, data, mask)
    -- print(string.format("lock write, offs=%x, data=%x, mask=%x", offset, data, mask))
end

function run()
    get_memory():install_write_tap(0xA1001A, 0xA1001B, "console device tx", callback)

    get_memory():install_read_tap(0xA13000, 0xA13001, "console device rx", magic_value_read)
    get_memory():install_read_tap(0xA13006, 0xA13007, "console device rx", rng_read)
    get_memory():install_read_tap(0xA13002, 0xA13003, "console device rx", p3_controller_read)
    get_memory():install_read_tap(0xA13004, 0xA13005, "console device rx", p4_controller_read)
    get_memory():install_read_tap(0xA1308E, 0xA1308F, "console device rx", server_state_read)
    get_memory():install_read_tap(0xA1308C, 0xA1308D, "console device rx", server_challenges_read)
    get_memory():install_read_tap(0xA1301E, 0xA1301F, "console device rx", lock_read)
    get_memory():install_read_tap(0xA13020, 0xA1308B, "console device rx", server_save_data_read)

    get_memory():install_write_tap(0xA13090, 0xA13091, "console device tx", game_state_write)
    get_memory():install_write_tap(0xA1301E, 0xA1301F, "console device tx", lock_write)
    get_memory():install_write_tap(0xA13092, 0xA13093, "console device tx", game_challenges_write)
    get_memory():install_write_tap(0xA13094, 0xA130FF, "console device tx", game_save_data_write)
end

run()
