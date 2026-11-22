if not BASIL_OBFUSCATED then
	BASIL_HASH = function(s) return s end
end
local key = "alpha-license-7741"
if BASIL_HASH(key) == BASIL_HASH("alpha-license-7741") then
	print("license ok")
else
	print("license denied")
end
print(BASIL_HASH("alpha-license-7741") == BASIL_HASH("a-different-token"))
