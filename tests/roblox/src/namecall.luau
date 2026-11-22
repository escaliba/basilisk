-- Isolates the __namecall vs __index divergence. On native Roblox, `obj:method()` with a
-- __namecall metamethod fires __namecall. Virtualized, `obj:method()` compiles to
-- index-then-call, so it fires __index instead. This is inherent to virtualization, not a bug.

local mt = {
	__namecall = function(self, ...)
		return "via-namecall", ...
	end,
	__index = function(self, key)
		return function(_, ...)
			return "via-index", ...
		end
	end,
}
local obj = setmetatable({}, mt)
print("namecall-result", obj:anything(1, 2))
