--!nocheck
-- Basilisk M6 — server-provisioned BASIL_ENCFUNC key pattern (64-hex key).
--
-- GOAL: the AEAD key that unlocks a protected function is NEVER shipped in this script. It is fetched at
-- runtime from YOUR server after YOUR server validates the session. Basilisk ships no network code and
-- no endpoints; YOU provide the transport (RemoteFunction, HttpService, executor request, ...). The
-- generated artifact will contain no key and no URL.
--
-- KEY MODEL: the 64-hex literal passed to BASIL_ENCFUNC is the COMPILE key the function is sealed with.
-- Your server must return that SAME key, and only to an entitled client. A wrong / missing / tampered
-- runtime key fails closed: the protected function never materializes (no partial plaintext).

-- Lets the file also run un-obfuscated (e.g. local testing); the real protection is the obfuscated build.
if not BASIL_OBFUSCATED then
	BASIL_ENCFUNC = function(fn) return fn end
end

-- (1) Fresh per-session challenge nonce. NONCE/CHALLENGE material only — never a secret key by itself.
local nonce = os.clock()

-- (2) Hand the nonce + an identity to YOUR transport and get the key back. THIS FUNCTION IS YOURS:
--     replace the body with a real HTTPS call to your auth server. The returned key must be
--     runtime-sourced (not a literal), or Basilisk's compile-time taint check rejects the build.
local function fetchSessionKey(challenge, sessionId)
	-- EXAMPLE ONLY. Your real code calls your server over HTTPS here, e.g.:
	--   local body = HttpService:JSONEncode({ nonce = challenge, session = sessionId })
	--   local res  = HttpService:PostAsync(MY_AUTH_URL, body)        -- YOUR endpoint, not Basilisk's
	--   return HttpService:JSONDecode(res).key
	-- The server validates entitlement, binds the key to `challenge`/`sessionId` (anti-replay), and
	-- returns the 64-hex key only on success.
	return _G.BASILISK_RUNTIME_KEY                                    -- externally-injected runtime value
end

local sessionKey = fetchSessionKey(nonce, _G.SESSION_ID)

-- (3) Seal the protected logic. The 64-hex literal is the COMPILE key (build-time, used to seal — it does
--     not appear in the shipped artifact); `sessionKey` is the RUNTIME key fetched above. They must match
--     for the function to unlock.
local protected = BASIL_ENCFUNC(function(user)
	return "welcome:" .. tostring(user)
end, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", sessionKey)

-- (4) Use it. With the wrong/missing/tampered key, `protected` fails closed (returns nothing).
print(protected("player1"))
