local function work(n)
	local a, b, c, d = 1, 2, 3, 5
	local s = 0
	for i = 1, n do
		local x = a * b + c - d
		local y = x - a + c
		a = b
		b = c
		c = d
		d = (x + y) % 251
		s = s + a - b + c - d + i
	end
	return s
end
print(work(45000))
