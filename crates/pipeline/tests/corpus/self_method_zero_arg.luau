local Item = {}
Item.__index = Item

function Item.new(n)
	return setmetatable({ n = n }, Item)
end

function Item:mark()
	self.hit = self.n
end

function Item:label()
	return self.n .. "!"
end

local function run(list)
	for _, item in ipairs(list) do
		local cur = item
		cur:mark()
	end
end

local function labels(list)
	local out = {}
	for _, item in ipairs(list) do
		local cur = item
		out[#out + 1] = cur:label()
	end
	return table.concat(out, ",")
end

local a, b = Item.new("x"), Item.new("y")
run({ a, b })
print(a.hit, b.hit)
print(labels({ a, b }))
