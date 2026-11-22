local base = { greet = function() return "hi" end }
local t = setmetatable({}, { __index = base })
print("index-table", t.greet())

local defaults = setmetatable({}, {
	__index = function(_, key)
		return "default:" .. key
	end,
})
print("index-func", defaults.missing)

local guarded = setmetatable({}, {
	__newindex = function(tbl, key, value)
		rawset(tbl, key, value * 2)
	end,
})
guarded.x = 21
print("newindex", guarded.x, rawget(guarded, "x"))

local counter = setmetatable({ hits = 0 }, {
	__index = function(self, _)
		rawset(self, "hits", self.hits + 1)
		return self.hits
	end,
})
print("dynamic", counter.a, counter.b, counter.hits)
