-- Usage: mame genesis -cart <path> -autoboot_script plugins/main.lua
package.path = package.path .. ";./plugins/?.lua"

local nspace = require('nspace')
local reader = require('reader')
local writer = require('writer')
local controller = require('controller')
local menu = require('menu')
local common = require('common')
local replay = require('replay')
local record = require('record')

local output_path = os.getenv('RECORDING') or 'output.mlen'
local input_path = os.getenv('REPLAY') or 'input.nspace'
local extend_last_stage = (os.getenv('EXTEND_LAST_STAGE') or "") == "true"

local recording = nspace.load(input_path)
local stage = 1
local trace = nil
local trace_ptr = 1
local first_time = true
local m
local ctrl = controller.new(common.IO_DATA, common.IO_CTRL)
local w = writer.new(ctrl)
local r = reader.new(ctrl)
local extend = false

local output = io.open(output_path, 'wb')
assert(output ~= nil, "Could not open output file " .. output_path)

local function write_frame(frame, keys)
  if not extend then
    io.write(string.format('frame=%d down=%s up=%s left=%s right=%s start=%s a=%s b=%s c=%s\n',
      frame, keys.down, keys.up, keys.left, keys.right, keys.start, keys.a, keys.b, keys.c))
  end
  -- Recording only contains key state changes using the following binary format:
  --
  -- <frame_number:u32><player_1_keys:u8><player_2_keys:u8><player_3_keys:u8><player_4_keys:u8>
  --
  -- This years' game is single player only, so only player 1 state is stored.
  -- The frame number is stored in little endian.
  output:write(common.pack_dword(frame) .. common.pack_dword(common.to_storage(keys)))
end

local function next_frame()
  assert(trace ~= nil)
  io.write(string.format("trace_ptr=%d/%d\n", trace_ptr, #trace))
  if trace_ptr > #trace then
    return nil, nil
  end
  local data = trace[trace_ptr]
  trace_ptr = trace_ptr + 1

  if extend then
    write_frame(data.frame, common.from_storage(data.keys))
  end
  return data.frame, common.from_storage(data.keys)
end

local function trace_end()
  assert(recording ~= nil)
  stage = stage + 1
  trace_ptr = 1
  io.write(string.format("stage=%d/%d\n", stage, #recording.stages))

  if stage > #recording.stages then
    _G.r:unbind()
    if extend then
      _G.w:start_from(_G.r)
    end
    _G.w:bind()
    emu.pause()
    manager.machine:popmessage("Unpause to record")
  else
    m:show()
  end
end

local function menu_callback(trace_name)
  assert(recording ~= nil)
  trace = recording.stages[stage][trace_name].frames

  if stage == #recording.stages and extend_last_stage then
    extend = true
  end

  if first_time then
    _G.r = replay.new(w, next_frame, trace_end)
    _G.r:bind()
    first_time = false
  else
    _G.r:advance()
  end
end

m = menu.new('Replayer', menu_callback)
_G.w = record.new(r, write_frame, function(frame)
  output:write(common.pack_dword(frame) .. common.pack_dword(0))
  output:close()
end)

if recording == nil then
  _G.w:bind()
else
  m:show()
end
