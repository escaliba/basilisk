local a, b, c = 1, 2, 3
print("multi", a, b, c)

a, b = b, a
print("swap", a, b)

local x, y, z = (function()
	return 10, 20, 30
end)()
print("spread", x, y, z)

local p, q
p, q = 7, 8
print("noinit", p, q)

local t = {}
t.a, t.b, t[1] = "x", "y", "z"
print("fields", t.a, t.b, t[1])

local m, n = 1
print("extra-names", m, n)
