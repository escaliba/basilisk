local function two() return 100, 200 end
local function three() return 1, 2, 3 end
local function fwd(...) return three() end
local a, b = two()
local t = { three() }
local c, d, e = three()
local p, q, r = fwd()
print(a, b, #t, c, d, e, p, q, r)
