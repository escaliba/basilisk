-- B-secondary regression guard: a >=4-element `for i=1,#t` loop printing EVERY element, unary/operand-
-- order prints, and Mul + `< K` runs (fuel for the Super8 Mul,LoadK,LtK and Super9 LoadK,LoadK shapes).
-- The corpus compares full per-line stdout (raw vs virtualized), so any dropped iteration or off-by-one
-- renumber introduced by a new super-op shape near these jumps/comparisons surfaces here.
local t = {5, 15, 25, 35, 45}
for i = 1, #t do
	print(t[i] * 2)
end

local a = 7
print(-a)
print(2 * a)
print(a * 2)

local sum = 0
for i = 1, #t do
	if t[i] < 30 then
		sum = sum + t[i] * 3
		print("lo: " .. t[i])
	else
		print("hi: " .. t[i])
	end
end
print("sum:", sum)

local function classify(x)
	local sq = x * x
	if sq < 100 then
		return "small"
	else
		return "big"
	end
end
for i = 1, #t do
	print(i .. " -> " .. classify(t[i]))
end
