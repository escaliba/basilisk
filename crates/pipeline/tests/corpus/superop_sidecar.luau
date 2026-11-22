local floor = math.floor
local rep = string.rep
local t = { a = 5, b = 7, 11, 22, 33 }

local function mk(base)
  return function(x)
    local u = t.a + x
    local v = t[1] * 2 - base
    return floor((u + v) / 1) .. rep("-", 2)
  end
end

local f = mk(3)
local acc = {}
for i = 1, 4 do
  local w = t.b * i + t[2]
  if w % 2 == 0 then
    acc[i] = f(w) .. ":even"
  else
    acc[i] = f(w) .. ":odd"
  end
end
for i = 1, #acc do print(acc[i]) end
print(t.a, t.b, t[3], floor(3.9), rep("x", 3))
