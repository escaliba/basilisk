local mt
mt = {
	__add = function(a, b)
		if b.bad then error("boom") end
		return setmetatable({ v = a.v + b.v }, mt)
	end,
}
local function wrap(v, bad)
	return setmetatable({ v = v, bad = bad }, mt)
end
local a = wrap(3)
local b = wrap(4)
local ok1, r1 = pcall(function() return (a + b).v end)
local ok2 = pcall(function() return (a + wrap(5, true)).v end)
print(ok1, r1, ok2)
local c = a + b
print(c.v)
