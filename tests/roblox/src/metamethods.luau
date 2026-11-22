-- Exercises __index (table and function), __newindex, and `:` method calls dispatched
-- through __index. Virtualized output should behave IDENTICALLY to the original on Roblox.

local Base = { kind = "base" }
Base.__index = Base
function Base:greet()
	return "hi from " .. self.kind
end
local obj = setmetatable({ kind = "obj" }, Base)
print("index-table", obj.greet ~= nil, obj:greet())

local proxy = setmetatable({}, {
	__index = function(_, key)
		return "computed:" .. key
	end,
})
print("index-func", proxy.anything, proxy.other)

local guarded = setmetatable({}, {
	__newindex = function(t, k, v)
		rawset(t, k, v * 10)
	end,
})
guarded.x = 5
print("newindex", guarded.x)

local Vec = {}
Vec.__index = Vec
function Vec.new(n)
	return setmetatable({ n = n }, Vec)
end
function Vec:double()
	return Vec.new(self.n * 2)
end
function Vec:get()
	return self.n
end
print("method-chain", Vec.new(3):double():double():get())
