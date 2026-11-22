local n = 5
if nil then
	n = 111
end
if 0 then
	n = n + 1
end
if "always" then
	n = n + 10
end
print(n)
