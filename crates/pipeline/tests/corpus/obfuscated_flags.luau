-- BASIL_OBFUSCATED: a compile-time true in obfuscated builds, nil (falsy) un-obfuscated. The dev and
-- obfuscated runs must print IDENTICALLY (the gated code is output-neutral: a dev shim, a silent
-- debug call, and equivalent prod/dev paths), while the obfuscated build dead-strips the dev branches
-- entirely. Exercises: `if not BASIL_OBFUSCATED` drop, `if BASIL_OBFUSCATED then/else`, an elseif
-- chain with a constant-true arm, and the name folded as a value.

if not BASIL_OBFUSCATED then
	-- dev-only shim so the un-obfuscated run doesn't error on the silent call below.
	function log(_) end
end

if not BASIL_OBFUSCATED then
	log("debug: starting") -- stripped when obfuscated; silent (no output) in dev
end

local function square(n) return n * n end

local result
if BASIL_OBFUSCATED then
	result = square(6) -- prod path
else
	result = square(6) -- dev path (same value)
end
print(result)

local mode
if false then
	mode = "never"
elseif BASIL_OBFUSCATED then
	mode = "ready" -- obfuscated: this arm wins
else
	mode = "ready" -- dev: falls through to here (same value)
end
print(mode)

local active = BASIL_OBFUSCATED or true
print(active and "on" or "off")
