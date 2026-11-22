if not BASIL_OBFUSCATED then
	BASIL_OPAQUE = function(v) return v end
	BASIL_CRASH = function() end
end
local authorized = true
if BASIL_OPAQUE(true) and authorized then
	print("granted")
else
	BASIL_CRASH()
end
