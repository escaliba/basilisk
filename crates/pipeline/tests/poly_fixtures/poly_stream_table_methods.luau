local Vec = {}
Vec.__index = Vec

function Vec.new(x, y)
	return setmetatable({ x = x, y = y }, Vec)
end

function Vec:add(o)
	return Vec.new(self.x + o.x, self.y + o.y)
end

function Vec:dot(o)
	return self.x * o.x + self.y * o.y
end

local a = Vec.new(1, 2)
local b = Vec.new(3, 4)
local sum = a:add(b)
print(sum.x, sum.y)

local d = 0
for i = 1, 1000 do
	d = d + a:dot(b)
end
print(d)

local grid = {}
for i = 1, 8 do
	grid[i] = {}
	for j = 1, 8 do
		grid[i][j] = i * 10 + j
	end
end
print(grid[3][4], grid[8][8])
