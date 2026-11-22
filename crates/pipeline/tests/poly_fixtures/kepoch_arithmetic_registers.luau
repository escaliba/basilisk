local function poly(x, y, z)
	return x * x + y * y - z * z + x * y - y * z + z * x
end
local s = 0
for i = 1, 300 do
	local a = i % 7
	local b = i % 5
	local c = i % 3
	s = s + poly(a, b, c)
end
print(s)
