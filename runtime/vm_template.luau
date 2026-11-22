return (function(unpack, pack, sub, unpacks, byte, char, concat, select, pairs, tostring, ...)
--[[BITALIAS]]
--[[INSTKEYS]]
--[[HEAVY_EARLY]]
local dead = false
--[[SURFACE_PREAMBLE]]

local genv = getfenv(1)
--[[SURFACE_MEME_01]]

--[[STRINGS]]
--[[NOTICE0]]

--[[B85DEC]]

--[[CRYPTO]]

local function add32(a, b)
	return (a + b) % 0x100000000
end

local function qr(a, b, c, d)
	a = (a + b) % 0x100000000; d = lrotate(bxor(d, a), 16)
	c = (c + d) % 0x100000000; b = lrotate(bxor(b, c), 12)
	a = (a + b) % 0x100000000; d = lrotate(bxor(d, a), 8)
	c = (c + d) % 0x100000000; b = lrotate(bxor(b, c), 7)
	return a, b, c, d
end

local function chachaBlock(key, nonce, counter)
	local x0, x1, x2, x3 = 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
	local x4, x5, x6, x7 = key[1], key[2], key[3], key[4]
	local x8, x9, x10, x11 = key[5], key[6], key[7], key[8]
	local x12, x13, x14, x15 = counter, nonce[1], nonce[2], nonce[3]
	local y0, y1, y2, y3 = x0, x1, x2, x3
	for _ = 1, 10 do
		x0, x4, x8, x12 = qr(x0, x4, x8, x12)
		x1, x5, x9, x13 = qr(x1, x5, x9, x13)
		x2, x6, x10, x14 = qr(x2, x6, x10, x14)
		x3, x7, x11, x15 = qr(x3, x7, x11, x15)
		x0, x5, x10, x15 = qr(x0, x5, x10, x15)
		x1, x6, x11, x12 = qr(x1, x6, x11, x12)
		x2, x7, x8, x13 = qr(x2, x7, x8, x13)
		x3, x4, x9, x14 = qr(x3, x4, x9, x14)
	end
	return {
		(x0 + y0) % 0x100000000, (x1 + y1) % 0x100000000, (x2 + y2) % 0x100000000, (x3 + y3) % 0x100000000,
		(x4 + key[1]) % 0x100000000, (x5 + key[2]) % 0x100000000, (x6 + key[3]) % 0x100000000, (x7 + key[4]) % 0x100000000,
		(x8 + key[5]) % 0x100000000, (x9 + key[6]) % 0x100000000, (x10 + key[7]) % 0x100000000, (x11 + key[8]) % 0x100000000,
		(x12 + counter) % 0x100000000, (x13 + nonce[1]) % 0x100000000, (x14 + nonce[2]) % 0x100000000, (x15 + nonce[3]) % 0x100000000,
	}
end

local function key8(w)
	return { w[1], w[2], w[3], w[4], w[5], w[6], w[7], w[8] }
end

--[[STREAMXOR]]

local function checksum(s)
	local h = 0x811C9DC5
	for k = 1, #s do
		h = bxor(lrotate(h, 5), byte(s, k))
	end
	return h
end

local function keyedTag(pkey, index, site, body)
	local h1 = bxor(pkey[1], index)
	local h2 = bxor(pkey[2], site)
	local k3, k4 = pkey[3], pkey[4]
	for k = 1, #body do
		local b = byte(body, k)
		h1 = (bxor(lrotate(h1, 5), b) + k3) % 0x100000000
		h2 = (bxor(lrotate(h2, 7), b) + k4) % 0x100000000
	end
	return bxor(h1, pkey[7]), bxor(h2, pkey[8])
end
--[[SURFACE_MEME_02]]

local genkey
local RSALT
local ENVDIG
local SK_SJ, SK_QK, SK_EJ, SK_FR, SK_ACT, ACTPROBES, FM1, FM2
--[[STRUCTKEY]]

local function fmix(h)
	h = bxor(h, rshift(h, 16))
	h = ((h % 65536) * FM1 + ((h // 65536) * FM1 % 65536) * 65536) % 0x100000000
	h = bxor(h, rshift(h, 15))
	h = ((h % 65536) * FM2 + ((h // 65536) * FM2 % 65536) * 65536) % 0x100000000
	h = bxor(h, rshift(h, 16))
	return h
end

--[[ACTDOMS]]
local function hostProbeA(pid)
	return fmix(bxor(SK_ACT[band(pid, 7) + 1], lrotate(pid, 13)))
end
local function actTicket(parent, pid)
	local t = fmix((bxor(parent, ACTDOM) + pid) % 0x100000000)
	return fmix(bxor(t, hostProbeA(pid)))
end
local function actRoot()
	return fmix(bxor(genkey[1], ACTROOTDOM))
end
--[[SURFACE_MEME_03]]

--[[DECOMPRESS]]

--[[SUPER]]
--[[POLYTABLE]]
--[[KEPOCHDEFS]]
--[[HEAVY_DECODE]]

--[[OPMASKKEY]]
--[[PAGESIZE]]
--[[OPMASK]]

--[[OPMASK2]]

--[[MAPKEY]]
local function pmix(pid, i)
	local h = bxor(MAPKEY, SK_QK[band(i, 7) + 1], lrotate(pid, 13), lrotate(i, 21))
	h = bxor(h, rshift(h, 16))
	h = lrotate(h, 13)
	h = bxor(h, rshift(h, 11))
	h = lrotate(h, 7)
	h = bxor(h, rshift(h, 17))
	return h
end
local function buildinvmap(pid)
	local perm = {}
	for k = 0, 255 do
		perm[k] = k
	end
	for i = 255, 1, -1 do
		local j = pmix(pid, i) % (i + 1)
		perm[i], perm[j] = perm[j], perm[i]
	end
	local inv = {}
	for k = 0, 255 do
		inv[perm[k]] = k
	end
	return inv
end
--[[SURFACE_MEME_04]]

local function decodeRange(proto, pos, fromIdx, count)
	local data = proto[11]
	local pid = proto[5]
	local code = proto[1]
	local imap = buildinvmap(pid)
	local olp = proto[24]
	local L0, L1, L2 = olp[1], olp[2], olp[3]
	local mpp = proto[25]
	local M0, M1, M2 = mpp[1], mpp[2], mpp[3]
	local GM = proto[26]
	local function u8()
		local v
		v, pos = unpacks(sB, data, pos)
		return v
	end
	--[[DR_VSM]]
	local last = fromIdx + count - 1
	for i = fromIdx, last do
		local op = imap[bxor(u8(), opmask(pid, i))]
		--[[DECODE]]
	end
end

local function decodeProto(proto)
	if proto[12] == false then
		return
	end
	decodeRange(proto, proto[12], 1, proto[13] or 0)
	proto[12] = false
end

local function wireDigest(pid, data, a, b)
	local h = MK
	h = bxor(lrotate(h, 7), pid)
	h = bxor(lrotate(h, 7), MAPKEY)
	for k = 1, 8 do
		h = bxor(lrotate(h, 7), SK_EJ[k])
	end
	for p = a, b - 1 do
		h = bxor(lrotate(h, 5), byte(data, p))
	end
	return bxor(h, rshift(h, 15))
end
--[[SURFACE_MEME_05]]

local function deserialize(data)
	local pos = 1
	local function u8()
		local v
		v, pos = unpacks(sB, data, pos)
		return v
	end
	local function u32()
		local v
		v, pos = unpacks(sI, data, pos)
		return v
	end
	--[[VARINTS]]
	local function rawbytes(n)
		local v = sub(data, pos, pos + n - 1)
		pos = pos + n
		return v
	end
	--[[SKIPV]]

	local saltWords = { u32(), u32(), u32() }

	local digest = 0x9E3779B9
	local pidNext = 0

	local function readProto(isRoot)
		local proto = { {}, {}, {}, {}, pidNext }
		pidNext = pidNext + 1
		local imap = buildinvmap(proto[5])
		local nsec = u8()
		for _ = 1, nsec do
			local tag = u8()
			local len = vu()
			local sectionEnd = pos + len
			if tag == 1 then
				proto[6] = fvu(proto[5], 1)
				proto[7] = fvu(proto[5], 2) ~= 0
				proto[8] = fvu(proto[5], 3)
				proto[24] = { fvu(proto[5], 160), fvu(proto[5], 161), fvu(proto[5], 162) }
				proto[25] = { fvu(proto[5], 163), fvu(proto[5], 164), fvu(proto[5], 165) }
				proto[26] = fvu(proto[5], 166)
			elseif tag == 2 then
				local cds = pos
				local n = vu()
				proto[11] = data
				proto[12] = pos
				proto[13] = n
				proto[14] = wireDigest(proto[5], data, cds, sectionEnd)
				local pstarts
				if isRoot then
					pstarts = {}
				end
				for i = 1, n do
					if isRoot and (i - 1) % PGSZ == 0 then
						pstarts[#pstarts + 1] = pos
					end
					local op = imap[bxor(u8(), opmask(proto[5], i))]
					digest = bxor(lrotate(digest, 7), op)
					--[[GSSKIP_PRE]]local m = SUPER[op]
					if m then
						for _ = 1, m do
							skipv()
						end
					else
						skipv()
						if LIVEB[op] then
							skipv()
						end
						if LIVEC[op] then
							skipv()
						end
					end--[[GSSKIP_POST]]
				end
				local pdg = {}
				local np = (n + PGSZ - 1) // PGSZ
				for pi = 1, np do
					pdg[pi] = u32()
				end
				proto[15] = pdg
				--[[TRAPSCEXP]]
				if isRoot then
					proto[16] = pstarts
				end
			elseif tag == 3 then
				local n = vu()
				--[[D1KREAD]]
				--[[CONSTSEC]]
			elseif tag == 4 then
				local n = vu()
				local upvals = proto[3]
				for i = 1, n do
					local fidx = 8 + 2 * (i - 1)
					upvals[i] = { [KIS] = fvu(proto[5], fidx) ~= 0, [KIX] = fvu(proto[5], fidx + 1) }
				end
			elseif tag == 5 then
				local n = vu()
				local protos = proto[4]
				for i = 1, n do
					protos[i] = readProto(false)
				end
			elseif tag == 8 then
				proto[23] = fvu(proto[5], 172)
				proto[21] = data
				proto[22] = pos
			end
			pos = sectionEnd
		end
		proto[14] = bxor(proto[14], bxor(lrotate(MK, 11), lrotate(MAPKEY, 23)))
		proto[14] = fmix((proto[14] + proto[6]) % 0x100000000)
		proto[14] = fmix((proto[14] + (proto[7] and 1 or 0)) % 0x100000000)
		proto[14] = fmix((proto[14] + proto[8]) % 0x100000000)
		proto[14] = fmix((proto[14] + #proto[3]) % 0x100000000)
		for i = 1, #proto[3] do
			proto[14] = fmix((proto[14] + (i - 1)) % 0x100000000)
			proto[14] = fmix((proto[14] + (proto[3][i][KIS] and 1 or 0)) % 0x100000000)
			proto[14] = fmix((proto[14] + proto[3][i][KIX]) % 0x100000000)
		end
		return proto
	end

	local main = readProto(true)
	return main, saltWords, digest
end
--[[SURFACE_MEME_06]]

--[[ENVPROBE]]

--[[LC1CANARY]]

--[[SHELLPROBEDECL]]
--[[PRECHECKDECL]]
local function deriveGenKey(saltWords, digest)
	local counter = digest
	--[[PROBEFOLD]]
	--[[LC1FOLD]]
	--[[SHELLPROBEFOLD]]
	--[[PRECHECKFOLD]]
	local ed = ENVDIG
	local k = {
		bxor(FIXED[1], ed[1]), bxor(FIXED[2], ed[2]), bxor(FIXED[3], ed[3]), bxor(FIXED[4], ed[4]),
		bxor(FIXED[5], ed[5]), bxor(FIXED[6], ed[6]), bxor(FIXED[7], ed[7]), bxor(FIXED[8], ed[8]),
	}
	return key8(chachaBlock(k, saltWords, counter))
end
--[[SURFACE_MEME_07]]

local KCAP = 8

--[[ROUTETABLE]]
--[[HEAVY_ROUTE]]

--[[HEAVY_HELPER]]
local function mpk(pid, kdg, ep)
	local k = bxor(genkey[2], pid)
	k = bxor(lrotate(k, 7), kdg)
	k = bxor(lrotate(k, 11), ep)
	return bxor(lrotate(k, 13), genkey[7])
end

local function psite(raw, pk, i)
	local rot = band(bxor(pk, i), 31)
	local t = lrotate(bxor(raw, pk), rot)
	t = bxor(lrotate(t, 11), bxor(pk, lrotate(i, 13)))
	return bxor(lrotate(t, 5), pk)
end
--[[SURFACE_MEME_08]]

--[[KGETDEFS]]

local KGR = { --[[KGETROUTE]] }
local function kroute(pid)
	return KGR[pid % #KGR + 1]
end

--[[UVACCESS]]

local function rg(t, i)
	return t[i]
end

local function rs(t, i, v)
	t[i] = v
end

--[[OPROUTE]]

--[[NATIVE]]

--[[PDG]]

--[[VPG]]

--[[KSITE]]

--[[ICAT]]
--[[NOTICE1]]
--[[SURFACE_MEME_09]]

local makeClosure

local function cep(pid, kdg, ticket)
	local e = bxor(lrotate(genkey[3], 9), pid)
	e = bxor(lrotate(e, 13), kdg)
	e = bxor(lrotate(e, 7), genkey[6])
	return bxor(bxor(lrotate(e, 11), genkey[2]), ticket)
end
--[[SURFACE_MEME_10]]

--[[ACTVM]]

--[[ISHARD]]

--[[ENCFUNC]]

--[[TRAPHELPERS]]

local function ensurePages(proto, upto)
	local pstarts = proto[16]
	if not pstarts then
		return
	end
	if upto > #pstarts then
		upto = #pstarts
	end
	local hw = proto[17] or 0
	if upto <= hw then
		return
	end
	for K = hw + 1, upto do
		local base = (K - 1) * PGSZ
		local count = PGSZ
		if base + count > proto[13] then
			count = proto[13] - base
		end
		decodeRange(proto, pstarts[K], base + 1, count)
		ipatchRange(proto, base + 1, base + count)
		ktokRange(proto, base + 1, base + count)
		if not _vpgpage(proto[1], base + 1, count, proto[15][K]) then
			dead = true
			return
		end
		--[[TRAPSPAGE]]
	end
	proto[17] = upto
end

makeClosure = (function()
--[[DISPATCHLABELS]]
--[[VMFUNCHEAD]]
	--[[CLOSURE_SETUP]]

	--[[VMFRAMEHEAD]]
		--[[FIRSTCALL]]
		--[[FRAME_INIT]]

		local pc = 1
		while true do
			if dead then
				return
			end
			local inst = code[pc]
			if inst == nil then
				ensurePages(proto, (pc - 1) // PGSZ + 1)
				if dead then
					return
				end
				--[[TRAPSFRAME]]
				inst = code[pc]
			end
			pc = pc + 1
			--[[INSTHEAD]]

				--[[DISPATCH]]
				--[[POLYSTREAM]]
		end
	end
	--[[VMFRAMETAIL]]
end
end)()
--[[SURFACE_MEME_11]]

--[[HEAVY_POST]]
--[[NOTICE2]]
--[[RGCONTAINER]]
--[[PAYLOAD]]

envProbe()
SK_SJ = structKey(ENVDIG, MK)
SK_QK = structKey(ENVDIG, MAPKEY)
SK_EJ = structKey(ENVDIG, bxor(lrotate(MK, 16), MAPKEY))
SK_FR = structKey(ENVDIG, bxor(lrotate(MK, 5), lrotate(MAPKEY, 19)))
SK_ACT = structKey(ENVDIG, ACTDOM)
ACTPROBES = { bxor(ENVDIG[1], ENVDIG[5]), bxor(ENVDIG[2], ENVDIG[6]), bxor(ENVDIG[3], ENVDIG[7]), bxor(ENVDIG[4], ENVDIG[8]) }
FM1 = MK - MK % 2 + 1
FM2 = MAPKEY - MAPKEY % 2 + 1
local mainProto, saltWords, digest
local _ok, _a, _b, _c = pcall(deserialize, PAYLOAD)
if _ok then
	mainProto, saltWords, digest = _a, _b, _c
else
	dead = true
	return
end
--[[SHELLPROBESET]]
--[[SHELLPROBESINK]]
--[[PRECHECKTABLE]]
--[[PRECHECKSET]]
genkey = deriveGenKey(saltWords, digest)
RSALT = bxor(bxor(genkey[1], lrotate(genkey[4], 11)), bxor(lrotate(genkey[7], 19), 2654435769))
if dead then
	return
end
mainProto[20] = actTicket(actRoot(), 0)
return makeClosure(mainProto, {})()
end)(table.unpack, table.pack, string.sub, string.unpack, string.byte, string.char, table.concat, select, pairs, tostring, ...)
