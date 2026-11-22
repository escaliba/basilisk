local function adder(base)
	return function(n)
		return base + n * 2
	end
end

local function sumTo(n)
	if n <= 0 then
		return 0
	end
	return n + sumTo(n - 1)
end

local f = adder(10)
local g = adder(1000)
local acc = 0
for i = 1, 5000 do
	acc = acc + f(i) - g(i)
end
print(acc)
print(f(7), g(7))
print(sumTo(50))
print(sumTo(0))
