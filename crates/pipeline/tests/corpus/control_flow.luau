local acc = {}
for i = 10, 2, -2 do
	table.insert(acc, i)
end
print("numfor", table.concat(acc, ","))

local total = 0
for _, v in ipairs({ 1, 2, 3, 4 }) do
	total += v
end
print("ipairs", total)

local p, n = 1, 1
while true do
	p *= 2
	n += 1
	if n > 5 then
		break
	end
end
print("while", p)

local r = 0
repeat
	r += 1
until r >= 3
print("repeat", r)

local evens = {}
for i = 1, 8 do
	if i % 2 == 1 then
		continue
	end
	table.insert(evens, i)
end
print("continue", table.concat(evens, ","))

local found = 0
for i = 1, 5 do
	for j = 1, 5 do
		if i * j == 12 then
			found += 1
			continue
		end
	end
end
print("nested-continue", found)
