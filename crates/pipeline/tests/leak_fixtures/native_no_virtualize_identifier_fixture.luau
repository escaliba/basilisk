if not BASIL_OBFUSCATED then
	function BASIL_NO_VIRTUALIZE(f) return f end
end

local checkNativeWhitelist = BASIL_NO_VIRTUALIZE(function(secretArgName)
	local hiddenLocalName = secretArgName * 3
	local nativeWhitelistDecision = hiddenLocalName > 10
	if nativeWhitelistDecision then
		return hiddenLocalName
	end
	return 0
end)

print(checkNativeWhitelist(5), checkNativeWhitelist(2))
