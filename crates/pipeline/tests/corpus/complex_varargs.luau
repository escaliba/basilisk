local function collect(...)
	local t = { ... }
	local s = 0
	for i = 1, #t do s = s + t[i] end
	return s, select("#", ...)
end
local function pt(...) return ... end
local function head(...) local a = ... return a end
local sum, cnt = collect(3, 6, 9, 12)
local x, y, z = pt(10, 20, 30)
print(sum, cnt, x, y, z, head(7, 8, 9))
