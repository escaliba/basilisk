local function make(env)
	local function f()
		return greeting .. " " .. name
	end
	setfenv(f, env)
	return f
end

local f = make(setmetatable({ greeting = "hello", name = "world" }, { __index = _G }))
print("setfenv", f())

local g = make({ greeting = "hi", name = "lua" })
print("isolated", g())
