if not BASIL_OBFUSCATED then
	BASIL_INLINE = function(f) return f end
	BASIL_NO_VIRTUALIZE = function(f) return f end
	BASIL_ENCFUNC = function(f) return f end
	BASIL_ENCFUNC_SEED = function(f) return f end
	BASIL_CRASH = function() end
	BASIL_HASH = function(s) return s end
	BASIL_OPAQUE = function(v) return v end
	BASIL_OPCODE = function() end
	BASIL_LINE = function() return 0 end

	BASIL_ENCSTR = function(s) return s end
	BASIL_ENCBUF = function(s) return buffer.fromstring(s) end
	BASIL_ENCNUM = function(n) return n end
	BASIL_PRECHECK = function() end
	BASIL_STACKALLOC = function(n, base)
		base = base or 1
		local store = {}
		return setmetatable({}, {
			__len = function() return n end,
			__index = function(_, k)
				if type(k) == "number" then return store[k] end
				if k == "clear" then return function(_, a, b) for i = a or base, b or (base + n - 1) do store[i] = nil end end end
				if k == "pack" then return function(_, a, b) return table.pack(table.unpack(store, a or base, b or (base + n - 1))) end end
				if k == "unpack" then return function(_, a, b) return table.unpack(store, a or base, b or (base + n - 1)) end end
				return nil
			end,
			__newindex = function(_, k, v) store[k] = v end,
		})
	end

	BASIL_ATTRIBUTES = function() end
	INLINE = function() end
	VM = function() end
	ENCRYPT = function() end
	UNROLL = function() end
	NONE = 0
	PROTECTED = 1
end
