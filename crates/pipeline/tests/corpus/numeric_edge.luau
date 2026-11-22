local function show(label, ...)
	print(label, ...)
end

show("small", 0, 1, -1, 2, -2, 42, -42, 255, 256, -256, 1000, -1000)
show("mid", 65535, 65536, 16777215, 16777216, -16777216)
show("intfloat", 2.0, 100.0, -7.0, 1.5e10)
show("pow2_32", 4294967296, -4294967296, 4294967295)
show("pow2_52", 4503599627370496, -4503599627370496)
show("above52", 4503599627370497, 9007199254740992, -9007199254740992)
show("floats", 0.5, -0.5, 3.14159, 2.5, -0.25, 1e-3)
show("special", 1 / 0, -1 / 0, 0 / 0)

local nz = -0.0
show("negzero", nz, 1 / nz, 1 / 0.0, nz == 0.0)

local acc = 0
for i = 1, 20 do
	acc = acc + i * 3
end
show("loopsum", acc)

local t = { 10, 20, 30, 40, 4503599627370496 }
show("index", t[1], t[3], t[5], #t)

local x = 4294967296
show("arith", x + 1, x - 1, x * 2, x // 3, x % 7, -x)

local bits = 0xFF00FF00
show("bits", bits, bit32.band(bits, 0x0F0F0F0F), bit32.rshift(bits, 8), 0b1010)

local sum = 0
for i = 4503599627370490, 4503599627370496 do
	sum = sum + (i - 4503599627370490)
end
show("bigfor", sum)
