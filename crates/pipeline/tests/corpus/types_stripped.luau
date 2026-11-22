-- Types are erased by lowering; this must behave identically once stripped.
type Point = { x: number, y: number }

local function dist(p: Point): number
	return math.sqrt(p.x * p.x + p.y * p.y)
end

local p: Point = { x = 3, y = 4 }
print("typed", dist(p))

local function id<T>(v: T): T
	return v
end
print("generic", id(42), id("s"))

local n = 5 :: number
print("assert", n + 1)

export type Public = string
local s: Public = "exported"
print("alias", s)
