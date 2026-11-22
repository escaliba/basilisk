local a = 100
a += 7
print("add", a)
a -= 17
print("sub", a)
a *= 2
print("mul", a)
a /= 4
print("div", a)
a %= 7
print("mod", a)
a ^= 3
print("pow", a)
a //= 4
print("floordiv", a)

local s = "a"
s ..= "b"
s ..= "c"
print("concat", s)

local t = { x = 10 }
t.x += 5
t["x"] *= 2
print("field", t.x)
