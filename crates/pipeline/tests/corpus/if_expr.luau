local function classify(n)
	return if n < 0 then "neg" elseif n == 0 then "zero" else "pos"
end
print("classify", classify(-5), classify(0), classify(9))

local x = (if true then 1 else 2) + (if false then 10 else 20)
print("arith", x)

local t = { v = if 3 > 2 then "y" else "n" }
print("infield", t.v)

local nested = if 1 == 1 then (if 2 == 2 then "both" else "first") else "neither"
print("nested", nested)
