local function counter()
	local n = 0
	return function()
		n += 1
		return n
	end
end
local c = counter()
print("counter", c(), c(), c())

local fns = {}
for i = 1, 3 do
	fns[i] = function() return i * 10 end
end
print("capture", fns[1](), fns[2](), fns[3]())

local function make()
	local acc = 0
	local function add(x) acc += x end
	local function get() return acc end
	return add, get
end
local add, get = make()
add(5)
add(7)
print("shared", get())
