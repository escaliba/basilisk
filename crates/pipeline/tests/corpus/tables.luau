local function multi()
	return 1, 2, 3
end

local t = {
	10,
	20,
	30,
	name = "x";
	[true] = "yes",
	nested = { a = 1, b = { 2, 3 } },
}
print("mixed", t[1], t[2], t[3], t.name, t[true], t.nested.a, t.nested.b[2])

local expand = { 0, multi() }
print("expand", #expand, expand[1], expand[2], expand[3], expand[4])

local trunc = { (multi()) }
print("trunc", #trunc, trunc[1])

local function pack(...)
	return { ... }
end
local v = pack("a", "b", "c")
print("vararg-table", #v, v[1], v[3])

local computed = { [1 + 1] = "two", ["k" .. "ey"] = "joined" }
print("computed", computed[2], computed.key)
