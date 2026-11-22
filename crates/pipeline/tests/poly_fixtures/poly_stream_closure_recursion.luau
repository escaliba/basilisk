local function makeCounter(start)
	local count = start
	return function()
		count = count + 1
		return count
	end
end

local function fib(n)
	if n < 2 then
		return n
	end
	return fib(n - 1) + fib(n - 2)
end

local c1 = makeCounter(10)
local c2 = makeCounter(100)
for _ = 1, 5 do
	c1()
	c2()
end
print(c1(), c2())
print(fib(20))
print(fib(0), fib(1))
