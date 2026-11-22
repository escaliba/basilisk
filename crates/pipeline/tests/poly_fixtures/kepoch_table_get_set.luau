local grid = {}
for i = 1, 10 do
	local row = {}
	grid[i] = row
	for j = 1, 10 do
		row[j] = i * j
	end
end
local sum = 0
for i = 1, 10 do
	local row = grid[i]
	for j = 1, 10 do
		sum = sum + row[j]
	end
end
print(sum)
