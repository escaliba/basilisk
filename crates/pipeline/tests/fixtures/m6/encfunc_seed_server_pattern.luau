--!nocheck
-- Basilisk M6 — server-provisioned BASIL_ENCFUNC_SEED pattern (numeric seed).
--
-- Identical deployment model to encfunc_server_key_pattern.luau, but the unlock secret is a NUMBER
-- (easier to transport/store than a 64-hex string). The compile seed and the runtime seed derive the
-- same 32-byte AEAD key via Basilisk's KDF; they must be equal for the function to unlock.
--
-- IMPORTANT (same caveat as M5): a numeric seed is CONVENIENCE, not extra strength. A small or
-- predictable seed is weaker than a 256-bit hex key. Use a WIDE, UNPREDICTABLE integer seed
-- (anywhere in [0, 2^53-1]) and fetch it from your server — never hardcode the runtime seed.

if not BASIL_OBFUSCATED then
	BASIL_ENCFUNC_SEED = function(fn) return fn end
end

-- (1) Fresh per-session challenge nonce (NOT the unlock seed — challenge material only).
local nonce = os.clock()

-- (2) YOUR transport: send nonce + identity to your server, receive the unlock SEED. Replace the body
--     with your real HTTPS call. The returned seed must be runtime-sourced (not a literal).
local function fetchSessionSeed(challenge, sessionId)
	-- EXAMPLE ONLY — your real code calls your server over HTTPS here and returns a number bound to the
	-- challenge/session. Basilisk provides no transport and ships no endpoint.
	return _G.BASILISK_RUNTIME_SEED                                  -- externally-injected runtime number
end

local sessionSeed = fetchSessionSeed(nonce, _G.SESSION_ID)

-- (3) Seal with the compile seed (build-time). The shipped artifact contains neither the seed nor the
--     derived key. `sessionSeed` must equal the compile seed for the unlock to succeed.
local protected = BASIL_ENCFUNC_SEED(function(user)
	return "welcome:" .. tostring(user)
end, 8675309424242, sessionSeed)

-- (4) Fails closed on a wrong/missing/tampered seed.
print(protected("player1"))
