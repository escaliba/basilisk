-- BASIL_NO_VIRTUALIZE direction (a): a native leaf CALLED FROM virtualized code.
-- Exercises varargs, multret, a string `:` method, a self-built metatable `:` method (native `:`
-- dispatch), and a numeric for inside the leaf. A genuine leaf: it touches only its params and
-- globals (setmetatable/ipairs/string) — no enclosing-local capture. The dev-stub makes it run
-- identically un-obfuscated.
if not BASIL_OBFUSCATED then
	function BASIL_NO_VIRTUALIZE(f) return f end
end

local crunch = BASIL_NO_VIRTUALIZE(function(base, ...)
	local meta = { __index = { add = function(self, n) self.total = self.total + n return self.total end } }
	local acc = setmetatable({ total = base }, meta)
	for _, v in ipairs({ ... }) do
		acc:add(v)
	end
	local tripled = 0
	for _ = 1, 3 do
		tripled = tripled + acc.total
	end
	return tripled, ("total=%d"):format(acc.total)
end)

local sum, label = crunch(100, 1, 2, 3, 4)
print(sum, label)
print(("ab"):rep(3))
