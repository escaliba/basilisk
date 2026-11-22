-- BASIL_NO_VIRTUALIZE direction (b): a native leaf that CALLS BACK INTO a virtualized function.
-- The callback re-enters the VM; multret and varargs must cross the boundary both ways. The dev-stub
-- makes it run identically un-obfuscated.
if not BASIL_OBFUSCATED then
	function BASIL_NO_VIRTUALIZE(f) return f end
end

-- native: forwards varargs to a callback value and returns whatever it returns (multret).
local apply = BASIL_NO_VIRTUALIZE(function(cb, ...)
	return cb(...)
end)

-- virtualized callbacks passed in as values.
local function combine(a, b, c) return a + b + c, a * b * c end
local function greet(name) return "hi " .. name end

local s, p = apply(combine, 2, 3, 4)
print(s, p)
print(apply(greet, "world"))

-- native leaf invoked repeatedly from a virtualized loop, accumulating.
local acc = 0
for i = 1, 5 do
	acc = acc + apply(combine, i, i, i)
end
print(acc)
