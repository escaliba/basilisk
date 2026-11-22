local a = 1 + 2
local b = 4 * 5
local c = 10 - 3
local s = "foo" .. "bar"
local cmp = (1 < 2) and "yes" or "no"
local d = 100 + 200 + 300
local nested = (2 + 3) * 4
print(a, b, c, s, cmp, d, nested)
if false then
	print("unreachable dead branch")
end
if true then
	print("always live")
end
if 1 == 2 then
	print("never")
else
	print("else taken")
end
print(#"hello")
print(not nil)
print(-5 + 5)
