local function fib(n)
	if n < 2 then return n end
	return fib(n - 1) + fib(n - 2)
end
local function make(base)
	return function(x) return base + x * 2 end
end
local f = make(10)
local g = make(100)
local s = 0
for i = 1, 200 do s = s + f(i) - g(i) end
print(s, fib(19))
