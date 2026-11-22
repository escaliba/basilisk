local function compute(n)
	local acc = 0
	local factor = 3
	for i = 1, n do
		local x = i * factor
		local y = x - 2
		acc = acc + y * 2
	end
	return acc
end

local total = 0
for k = 1, 10000 do
	total = total + compute(5)
end
print(total)
print(compute(100))
print(compute(0))
