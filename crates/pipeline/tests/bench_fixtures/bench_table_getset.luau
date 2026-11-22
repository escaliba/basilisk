local function work(n)
	local t = {}
	for i = 1, 64 do t[i] = i end
	local s = 0
	for i = 1, n do
		local k = (i % 64) + 1
		local v = t[k]
		t[k] = v + i
		s = s + t[((i * 3) % 64) + 1]
	end
	return s
end
print(work(3000))
