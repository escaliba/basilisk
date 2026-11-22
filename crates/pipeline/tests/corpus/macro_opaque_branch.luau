if not BASIL_OBFUSCATED then
	BASIL_OPAQUE = function(v) return v end
end
local valid = true
if BASIL_OPAQUE(true) and valid then
	print("path A")
end
if BASIL_OPAQUE(false) then
	print("unreachable")
else
	print("path B")
end
local x = BASIL_OPAQUE(true) and 10 or 20
print(x)
local function f() return BASIL_OPAQUE(true) end
print(f())
