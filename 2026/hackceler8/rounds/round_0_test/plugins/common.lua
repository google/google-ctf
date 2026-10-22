local mod = {}
mod.IO_BASE_START = 0xa10000
mod.IO_BASE_END = 0xa1000f
mod.IO_DATA = mod.IO_BASE_START + 2
mod.IO_CTRL = mod.IO_BASE_START + 8

local function bit_to_bool(field, bit)
  return (field & (1 << bit)) ~= 0
end

local function bool_to_bit(val, bit)
  if val then
    return 1 << bit
  else
    return 0
  end
end

function mod.to_storage(keys)
  return bool_to_bit(keys.b, 0) |
      bool_to_bit(keys.c, 1) |
      bool_to_bit(keys.down, 2) |
      bool_to_bit(keys.left, 3) |
      bool_to_bit(keys.right, 4) |
      bool_to_bit(keys.up, 5) |
      bool_to_bit(keys.a, 6) |
      bool_to_bit(keys.start, 7)
end

function mod.from_storage(data)
  return {
    b = bit_to_bool(data, 0),
    c = bit_to_bool(data, 1),
    down = bit_to_bool(data, 2),
    left = bit_to_bool(data, 3),
    right = bit_to_bool(data, 4),
    up = bit_to_bool(data, 5),
    a = bit_to_bool(data, 6),
    start = bit_to_bool(data, 7),
  }
end

function mod.to_bits(keys)
  -- See https://plutiedev.com/controllers#reading for mapping
  high_bits = bool_to_bit(not keys.up, 0) |
      bool_to_bit(not keys.down, 1) |
      bool_to_bit(not keys.left, 2) |
      bool_to_bit(not keys.right, 3) |
      bool_to_bit(not keys.b, 4) |
      bool_to_bit(not keys.c, 5)
  low_bits = bool_to_bit(not keys.a, 4) |
      bool_to_bit(not keys.start, 5)

  return high_bits, low_bits
end

function mod.from_bits(high_bits, low_bits)
  -- See https://plutiedev.com/controllers#reading for mapping
  return {
    up = not bit_to_bool(high_bits, 0),
    down = not bit_to_bool(high_bits, 1),
    left = not bit_to_bool(high_bits, 2),
    right = not bit_to_bool(high_bits, 3),
    b = not bit_to_bool(high_bits, 4),
    c = not bit_to_bool(high_bits, 5),
    a = not bit_to_bool(low_bits, 4),
    start = not bit_to_bool(low_bits, 5),
  }
end

function mod.unpack(bytes, width)
  assert(width > 0, "width must be positive, but was " .. width)
  assert(#bytes == width, "expected the length of input to be " .. width .. ", but was " .. #bytes)
  local val = 0
  for i = width, 1, -1 do
    val = (val << 8) + string.byte(bytes:sub(i, i))
  end
  return val
end

function mod.pack(n, width)
  assert(width > 0, "width must be positive, but was " .. width)
  local bytes = {}
  for _ = 1, width do
    table.insert(bytes, string.char(n & 0xff))
    n = n >> 8
  end
  return table.concat(bytes)
end

function mod.unpack_byte(bytes)
  return mod.unpack(bytes, 1)
end

function mod.pack_byte(n)
  return mod.pack(n, 1)
end

function mod.unpack_dword(bytes)
  return mod.unpack(bytes, 4)
end

function mod.pack_dword(n)
  return mod.pack(n, 4)
end

return mod
