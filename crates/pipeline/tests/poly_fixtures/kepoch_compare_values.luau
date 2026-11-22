local function classify(n, lo, hi, mid)
	local r = 0
	if n < lo then r = r + 1 end
	if n <= hi then r = r + 2 end
	if n == mid then r = r + 4 end
	if n >= hi then r = r + 8 end
	return r
end
local t = 0
for i = 1, 40 do
	t = t + classify(i, 10, 20, 15)
end
print(t)
