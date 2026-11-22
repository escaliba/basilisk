Gcount = 0
Gname = "start"
Gcount = Gcount + 5
Gname = Gname .. "-end"
for i = 1, 4 do
	Gcount = Gcount + i
end
if Gcount > 10 then
	Gflag = "hi"
else
	Gflag = "lo"
end
print("global", Gcount, Gname, Gflag)

local function make_counter()
	local n = 0
	local function inc(by)
		n = n + by
	end
	local function get()
		return n
	end
	return inc, get
end
local inc, get = make_counter()
inc(3)
inc(4)
for i = 1, 3 do
	inc(i)
end
print("upval", get())

local shared = 0
local function bump()
	shared = shared + 1
end
local function scale()
	shared = shared * 10
end
bump()
scale()
bump()
print("shared-upval", shared)

local t = { x = 1 }
t.x = t.x + 100
t.y = 2
t[3] = "three"
for i = 1, 3 do
	t["k" .. i] = i * i
end
if t.x > 50 then
	t.branch = "yes"
end
print("settable", t.x, t.y, t[3], t.k1, t.k2, t.k3, t.branch)

local guarded = setmetatable({}, {
	__newindex = function(tbl, key, value)
		rawset(tbl, key, value * 3)
	end,
})
guarded.a = 5
if true then
	guarded.b = 7
end
for i = 1, 2 do
	guarded["z" .. i] = i
end
print("newindex", rawget(guarded, "a"), rawget(guarded, "b"), rawget(guarded, "z1"), rawget(guarded, "z2"))
