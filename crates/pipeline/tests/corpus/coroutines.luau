local co = coroutine.create(function(a, b)
	local c = coroutine.yield(a + b)
	local d = coroutine.yield(c * 2)
	return d - 1
end)

print("co1", coroutine.resume(co, 3, 4))
print("co2", coroutine.resume(co, 10))
print("co3", coroutine.resume(co, 100))
print("co4", coroutine.resume(co))
print("status", coroutine.status(co))

local gen = coroutine.wrap(function()
	for i = 1, 3 do
		coroutine.yield(i * i)
	end
end)
print("wrap", gen(), gen(), gen())
