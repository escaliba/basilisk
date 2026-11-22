-- error level 0 keeps messages position-free, so output is round-trip stable.
local ok, err = pcall(function()
	error("boom", 0)
end)
print("pcall1", ok, err)

local ok2, err2 = pcall(function()
	error({ code = 7 })
end)
print("pcall2", ok2, type(err2), err2.code)

local function risky(n)
	if n < 0 then
		error("negative", 0)
	end
	return n * 2
end
print("ok-call", pcall(risky, 5))
print("err-call", pcall(risky, -1))

local function handler(e)
	return "handled:" .. e
end
print("xpcall", xpcall(function()
	error("xx", 0)
end, handler))

local ok3, err3 = pcall(function()
	local inner_ok, inner_err = pcall(function()
		error("inner", 0)
	end)
	assert(not inner_ok)
	error("outer:" .. inner_err, 0)
end)
print("nested", ok3, err3)
