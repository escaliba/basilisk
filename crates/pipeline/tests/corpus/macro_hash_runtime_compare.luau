if not BASIL_OBFUSCATED then
	BASIL_HASH = function(s) return s end
end
local short = "abc"
local long = "this-is-a-deliberately-long-license-token-that-exceeds-sixty-four-bytes-to-exercise-multi-block-sha256"
print(BASIL_HASH(short) == BASIL_HASH("abc"))
print(BASIL_HASH(long) == BASIL_HASH("this-is-a-deliberately-long-license-token-that-exceeds-sixty-four-bytes-to-exercise-multi-block-sha256"))
print(BASIL_HASH(short) == BASIL_HASH(long))
