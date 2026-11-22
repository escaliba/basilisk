-- Exercises the per-call-frame flatten block-ID memo across frame boundaries: recursion (many frames
-- of one proto), coroutine yield/resume (memo must survive a suspended frame), and pcall error unwind
-- (memo must die with the aborted frame). Many branches per function push the dispatcher past KCAP=8,
-- so a cross-frame leak or premature reuse would route wrong and diverge from the raw run.
local function deep(n, acc)
	if n <= 0 then
		return acc
	end
	if acc % 2 == 0 then acc = acc + 1 else acc = acc + 3 end
	if acc % 3 == 0 then acc = acc + 5 else acc = acc + 7 end
	if acc % 5 == 0 then acc = acc + 11 else acc = acc + 13 end
	if acc % 7 == 0 then acc = acc + 17 else acc = acc + 19 end
	if acc % 11 == 0 then acc = acc + 23 else acc = acc + 29 end
	return deep(n - 1, acc % 1000003)
end

local function co_worker(base)
	local s = base
	for i = 1, 8 do
		if i % 2 == 0 then s = s + i else s = s + 2 * i end
		if i % 3 == 0 then s = s + 100 else s = s + 7 end
		coroutine.yield(s)
	end
	return s
end

local function may_err(x)
	if x % 4 == 0 then
		error("boom")
	end
	if x % 2 == 0 then
		return x * 2
	end
	if x % 3 == 0 then
		return x * 3
	end
	return x + 1
end

print(deep(30, 1))

local co = coroutine.wrap(co_worker)
local acc = 0
for _ = 1, 8 do
	acc = acc + co(3)
end
print(acc)

local ok_sum, err_count = 0, 0
for i = 1, 40 do
	local ok, v = pcall(may_err, i)
	if ok then
		ok_sum = ok_sum + v
	else
		err_count = err_count + 1
	end
end
print(ok_sum, err_count)

-- Two independent closures of the same proto, interleaved, must not share memo state.
local function make_counter()
	return function(x)
		local r = 0
		if x % 2 == 0 then r = 2 else r = 1 end
		if x % 3 == 0 then r = r + 30 else r = r + 3 end
		if x % 5 == 0 then r = r + 500 else r = r + 5 end
		return r
	end
end
local a, b = make_counter(), make_counter()
local mix = 0
for i = 1, 20 do
	mix = mix + a(i) - b(i) + a(i * 2)
end
print(mix)
