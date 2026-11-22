local mt = { __add = function(self, n) return n + 1000 end }
local t = setmetatable({}, mt)
print(t + 1)
local u = { v = 2 }
print(u.v + 3)
local function f() return 7 end
print(f() + 1)
