local Vec = {}
Vec.__index = Vec
function Vec.new(x, y)
	return setmetatable({ x = x, y = y }, Vec)
end
function Vec:add(other)
	return Vec.new(self.x + other.x, self.y + other.y)
end
function Vec:scale(k)
	return Vec.new(self.x * k, self.y * k)
end
function Vec:unpack()
	return self.x, self.y
end

local a = Vec.new(1, 2)
local b = Vec.new(3, 4)
print("chain", a:add(b):scale(2):unpack())

local s = "Hello, World"
print("strmethods", s:upper(), s:sub(1, 5), s:len())
print("parenmethod", ("%d-%s"):format(7, "x"))

local function describe(arg)
	return type(arg) .. ":" .. tostring(arg)
end
print("strcall", describe"hello")

local function count(t)
	return #t
end
print("tablecall", count{ 1, 2, 3, 4 })
