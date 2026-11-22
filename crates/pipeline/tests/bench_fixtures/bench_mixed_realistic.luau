local function classify(x)
	if x % 2 == 0 then return "even" end
	if x % 3 == 0 then return "three" end
	return "other"
end
local function work(n)
	local counts = { even = 0, three = 0, other = 0 }
	local s = 0
	for i = 1, n do
		local c = classify(i)
		counts[c] = counts[c] + 1
		if i % 5 == 0 then s = s + i else s = s - 1 end
		s = s + #c
	end
	return s, counts.even, counts.three, counts.other
end
print(work(750))
