-- STEP-0 for super-ops (4c-4): long straight-line runs of catalogue shapes (GetGlobal/LoadK,
-- Move/LoadK/GetTable, GetTable/Move) sitting adjacent to loop back-jumps, branches, calls and
-- returns, the same shapes repeated (slot reuse), and a metamethod fired from inside a run.

local cfg = { base = 10, scale = 3, label = "run" }
local mt = setmetatable({ v = 7 }, { __add = function(a, b) return a.v + b end })

local function compute(n)
    -- straight-line run (table reads + locals + arithmetic), right before a loop
    local a = cfg.base
    local b = cfg.scale
    local c = cfg.base + cfg.scale
    local acc = a * b + c
    for i = 1, n do
        -- run inside the loop body, adjacent to the back-jump
        local x = cfg.base
        local y = cfg.scale
        acc = acc + x * y + i
        acc = acc - cfg.scale
    end
    -- run after the loop, before a branch
    local p = cfg.base
    local q = cfg.scale
    if acc > p * q then
        acc = acc + cfg.base
    else
        acc = acc - cfg.scale
    end
    return acc
end

local function build()
    -- repeated table-construction shapes
    local t = {}
    t.a = cfg.base
    t.b = cfg.scale
    t.c = cfg.label
    local u = {}
    u.a = cfg.scale
    u.b = cfg.base
    u.c = cfg.label
    return t.a + t.b + u.a + u.b
end

print(compute(4))
print(compute(7))
print(build())
print(mt + 5)
print(cfg.label .. ":" .. tostring(compute(2)))
return compute(3) + build()
