local obj = { nested = {} }
function obj.greet(name)
	return "hi " .. name
end
function obj.nested.deep(x)
	return x * 2
end
function obj:method(y)
	return self.tag .. y
end
obj.tag = "T"
print("dotted", obj.greet("a"), obj.nested.deep(5), obj:method("z"))

local function outer(n)
	local function inner(m)
		return m + n
	end
	return inner
end
print("nested-fn", outer(10)(5))

local adder = function(...)
	local s = 0
	for _, v in ipairs({ ... }) do
		s += v
	end
	return s
end
print("anon-vararg", adder(1, 2, 3))

local function variadic(prefix, ...)
	return prefix .. table.concat({ ... }, "-")
end
print("named+vararg", variadic("p:", "a", "b", "c"))
