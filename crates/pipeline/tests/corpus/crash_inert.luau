-- BASIL_CRASH present but INERT: the guard is a RUNTIME false (`local armed = false`), not a literal
-- `if false` (which the BASIL_OBFUSCATED fold would strip). So OP_CRASH is compiled into the
-- never-taken branch and exercised structurally through every pass (cff/junk/opaque/fuse/renumber),
-- while the program runs normally and prints identically in dev and obfuscated. A FIRING crash hangs,
-- so it can't live in the stdout-comparison corpus — that path is the separate timeout-bounded test.
if not BASIL_OBFUSCATED then
	function BASIL_CRASH() end
end

local armed = false
if armed then
	BASIL_CRASH()
end
print("crash inert: ok")
