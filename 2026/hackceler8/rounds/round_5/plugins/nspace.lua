local common = require('common')

local function endswith(s, suffix)
  return s:sub(- #suffix) == suffix
end

local function chomp(bytes, n)
  assert(#bytes >= n, "length of input must be equal or greater to " .. n .. ", but was " .. #bytes)
  return bytes:sub(1, n), bytes:sub(n + 1)
end

local function read_frame(data)
  local keys
  local frame, rest = chomp(data, 4)
  keys, rest = chomp(rest, 4)

  return {
    frame = common.unpack_dword(frame),
    keys = common.unpack_dword(keys)
  }, rest
end

local function read_bare_trace(data)
  local frames = {}
  while #data > 0 do
    local frame
    frame, data = read_frame(data)
    table.insert(frames, frame)
  end

  return frames
end

local function read_trace(data)
  local frame_count
  local frames = {}
  local flags, rest = chomp(data, 1)
  frame_count, rest = chomp(rest, 4)

  for n = 1, common.unpack_dword(frame_count) do
    frames[n], rest = read_frame(rest)
  end

  return {
    flags = common.unpack_byte(flags),
    frames = frames
  }, rest
end

local function read_stage(data)
  local a, b, c, rest

  a, rest = read_trace(data)
  b, rest = read_trace(rest)
  c, rest = read_trace(rest)

  return {
    a = a,
    b = b,
    c = c
  }, rest
end

local function read_stages(data)
  local count, rest = chomp(data, 1)

  local stages = {}
  for n = 1, common.unpack_byte(count) do
    local stage
    stage, rest = read_stage(rest)
    stages[n] = stage
  end

  return stages
end

local function load(path)
  f = io.open(path, "rb")
  if f == nil then
    return nil
  end
  data = f:read("a")
  f:close()
  if endswith(path, ".mlen") then
    return {
      stages = {
        {
          a = {
            flags = 0,
            frames = read_bare_trace(data)
          },
          b = {
            flags = 0,
            frames = {}
          },
          c = {
            flags = 0,
            frames = {}
          }
        }
      }
    }
  elseif endswith(path, ".nspace") then
    return {
      stages = read_stages(data)
    }
  else
    error("Unsupported file format: " .. path)
  end
end

return {
  load = load
}
