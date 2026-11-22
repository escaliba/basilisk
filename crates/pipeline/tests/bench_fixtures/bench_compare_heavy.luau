local function work(n)
	local a, b, c = 3, 7, 5
	local s = 0
	for i = 1, n do
		if a < b then s = s + 1 end
		if b <= c then s = s + 2 end
		if a == c then s = s + 4 end
		if b >= a then s = s + 8 end
		a = (a + i) % 11
		b = (b + a) % 13
		c = (c + b) % 7
	end
	return s
end
print(work(650))
