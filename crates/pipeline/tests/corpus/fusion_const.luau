local n = 7
print(n + 3)
print(n - 3)
print(n * 3)
print(n / 2)
print(n % 4)
print(n ^ 2)
print(n // 2)
print(n .. "!")
print(n == 7)
print(n ~= 7)
print(n < 10)
print(n <= 7)
print(n > 3)
print(n >= 8)

local Vec = {}
Vec.__index = Vec

local function v(x)
	return setmetatable({ x = x }, Vec)
end

local function scalar(b)
	if type(b) == "table" then
		return b.x
	end
	return b
end

function Vec.__add(a, b)
	return v(a.x + scalar(b))
end

function Vec.__sub(a, b)
	return v(a.x - scalar(b))
end

function Vec.__mul(a, b)
	return v(a.x * scalar(b))
end

function Vec.__concat(a, b)
	local function s(o)
		if type(o) == "table" then
			return "v" .. o.x
		end
		return tostring(o)
	end
	return s(a) .. "|" .. s(b)
end

function Vec.__lt(a, b)
	return a.x < scalar(b)
end

function Vec.__le(a, b)
	return a.x <= scalar(b)
end

local p = v(5)
print((p + 2).x)
print((p - 2).x)
print((p * 3).x)
print(p .. "z")
