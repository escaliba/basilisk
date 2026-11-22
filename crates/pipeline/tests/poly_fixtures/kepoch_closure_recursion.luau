local function makeAdder(base)
	return function(n)
		return base + n
	end
end
local function fib(n)
	if n < 2 then return n end
	return fib(n - 1) + fib(n - 2)
end
local f = makeAdder(100)
local g = makeAdder(1000)
local s = 0
for i = 1, 15 do
	s = s + f(i) - g(i)
end
print(s, f(5), g(5))
print(fib(18))
