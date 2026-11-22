local function sum(...)
	local total = 0
	for _, v in ipairs({ ... }) do
		total += v
	end
	return total
end

local function forward(...)
	return sum(...), select("#", ...)
end

print("sum", sum(1, 2, 3, 4))
print("forward", forward(10, 20, 30))

local packed = table.pack(1, nil, 3)
print("pack", packed.n, packed[1], packed[2], packed[3])
print("unpack", table.unpack({ 7, 8, 9 }))
print("select", select(2, "a", "b", "c"))

local function head(first, ...)
	return first, select("#", ...)
end
print("head", head("x", "y", "z"))
