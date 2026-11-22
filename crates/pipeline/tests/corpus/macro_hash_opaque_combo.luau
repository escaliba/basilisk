if not BASIL_OBFUSCATED then
	BASIL_HASH = function(s) return s end
	BASIL_OPAQUE = function(v) return v end
	BASIL_CRASH = function() end
end
local key = "combo-token-xyz"
if BASIL_OPAQUE(true) and BASIL_HASH(key) == BASIL_HASH("combo-token-xyz") then
	print("combo ok")
else
	BASIL_CRASH()
end
