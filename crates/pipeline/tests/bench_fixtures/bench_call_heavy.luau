local function add(a, b)
	return a + b
end

local function sink(x)
	return
end

local function step(acc, i)
	sink(i)
	local u = add(acc, i)
	sink(u)
	local v = add(u, 1)
	return v
end

local function work(n)
	local acc = 0
	for i = 1, n do
		acc = step(acc, i)
		sink(acc)
	end
	return acc
end

print(work(2500))
