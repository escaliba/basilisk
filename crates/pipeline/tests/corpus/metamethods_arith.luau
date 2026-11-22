local Vec = {}
Vec.__index = Vec

local function v(x, y)
	return setmetatable({ x = x, y = y }, Vec)
end

function Vec.__add(a, b)
	return v(a.x + b.x, a.y + b.y)
end

function Vec.__sub(a, b)
	return v(a.x - b.x, a.y - b.y)
end

function Vec.__mul(a, b)
	if type(a) == "number" then
		return v(b.x * a, b.y * a)
	elseif type(b) == "number" then
		return v(a.x * b, a.y * b)
	end
	return v(a.x * b.x, a.y * b.y)
end

function Vec.__div(a, b)
	return v(a.x / b.x, a.y / b.y)
end

function Vec.__mod(a, b)
	return v(a.x % b.x, a.y % b.y)
end

function Vec.__pow(a, b)
	return v(a.x ^ b.x, a.y ^ b.y)
end

function Vec.__unm(a)
	return v(-a.x, -a.y)
end

local function show(o)
	if type(o) == "table" then
		return "(" .. o.x .. "," .. o.y .. ")"
	end
	return tostring(o)
end

function Vec.__concat(a, b)
	return show(a) .. "|" .. show(b)
end

function Vec.__eq(a, b)
	return a.x == b.x and a.y == b.y
end

function Vec.__lt(a, b)
	return a.x * a.x + a.y * a.y < b.x * b.x + b.y * b.y
end

function Vec.__le(a, b)
	return a.x * a.x + a.y * a.y <= b.x * b.x + b.y * b.y
end

local p = v(6, 8)
local q = v(1, 2)

print("add", show(p + q))
print("sub", show(p - q), show(q - p))
print("mul", show(p * q), show(p * 3), show(3 * p))
print("div", show(p / q), show(q / p))
print("mod", show(p % q))
print("pow", show(p ^ q))
print("unm", show(-p))
print("concat", p .. q, q .. p)
print("concat_mix", p .. 5, 5 .. p)
print("eq", p == q, p == v(6, 8))
print("lt", p < q, q < p)
print("le", p <= q, p <= p, q <= p)
