local function make()
	local shared = 100
	local function add(n) shared = shared + n end
	local function read() return shared end
	return add, read
end
local add, read = make()
add(5) add(10)
local fns = {}
for i = 1, 4 do
	local cap = i * 10
	fns[i] = function() return cap end
end
print(read(), fns[1]() + fns[2]() + fns[3]() + fns[4]())
