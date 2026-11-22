// Verified Luau samples and macro examples for the Basilisk playground.
// Every snippet below obfuscates and runs correctly through the public engine.

export const DEFAULT_SAMPLE = `local function fib(n)
    if n < 2 then return n end
    return fib(n - 1) + fib(n - 2)
end

local total = 0
for i = 1, 10 do
    total = total + fib(i)
end
print("fib sum:", total)
`;

export const SAMPLES = [
  { name: "Fibonacci", source: DEFAULT_SAMPLE },
  {
    name: "Closures & upvalues",
    source: `local function counter(start)
    local n = start
    return function()
        n = n + 1
        return n
    end
end

local next = counter(40)
print(next(), next())
`,
  },
  {
    name: "Tables & metatables",
    source: `local Vec = {}
Vec.__index = Vec

function Vec.new(x, y)
    return setmetatable({ x = x, y = y }, Vec)
end

function Vec:sum()
    return self.x + self.y
end

print("sum:", Vec.new(19, 23):sum())
`,
  },
];

// Macro examples — see docs/MACROS.md. Call-site forms matter; keep these exact.
export const MACROS = [
  {
    name: "BASIL_INLINE",
    source: `local add = BASIL_INLINE(function(a, b) return a + b end)
local r = add(19, 23)
print("inline:", r)
`,
  },
  {
    name: "BASIL_OPAQUE",
    source: `if BASIL_OPAQUE(true) then print("opaque branch taken") end
`,
  },
  {
    name: "BASIL_HASH",
    source: `print("hash match:", BASIL_HASH("abc") == BASIL_HASH("abc"))
`,
  },
  {
    name: "BASIL_STACKALLOC",
    source: `local v = BASIL_STACKALLOC(2)
v[1] = 40
v[2] = 2
print("stackalloc:", v[1] + v[2])
`,
  },
  {
    name: "BASIL_ENCSTR",
    source: `local s = BASIL_ENCSTR("sealed-secret")
print("encstr:", s)
`,
  },
  {
    name: "BASIL_NO_VIRTUALIZE",
    source: `local g = BASIL_NO_VIRTUALIZE(function(x) return x * 2 end)
print("native:", g(21))
`,
  },
];
