local function noret()
	return
end

local function condret(x)
	if x > 0 then
		return
	end
	return "neg", x
end

local function tail_noret()
	return noret()
end

local function collect(...)
	return select("#", ...)
end

noret()
tail_noret()

local a, b = condret(5)
print(a, b)
local c, d = condret(-3)
print(c, d)

print(collect(noret()))
print(collect(condret(2)))
print(collect(condret(-4)))
print(collect(tail_noret()))

local function passthrough(...)
	return ...
end
print(select("#", passthrough(noret())))
print(passthrough(condret(-7)))
