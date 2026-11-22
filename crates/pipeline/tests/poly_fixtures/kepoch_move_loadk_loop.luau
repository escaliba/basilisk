local function run()
	local a = 1
	local b = 2
	local c = 3
	local acc = 0
	for i = 1, 500 do
		local x = a
		a = b
		b = c
		c = x
		acc = acc + a - b + c
	end
	return acc
end
print(run())
print(run())
