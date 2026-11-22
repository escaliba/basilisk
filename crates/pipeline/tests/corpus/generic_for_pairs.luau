local dict = { banana = 3, apple = 1, cherry = 2 }

local keys = {}
for key in pairs(dict) do
	table.insert(keys, key)
end
table.sort(keys)

local parts = {}
for _, key in ipairs(keys) do
	table.insert(parts, key .. "=" .. tostring(dict[key]))
end
print("pairs", table.concat(parts, ","))

local sum = 0
for index, value in ipairs({ 5, 10, 15 }) do
	sum += index * value
end
print("indexed", sum)
