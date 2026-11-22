local function add(a, b)
    return a + b
end

local total = 0
for i = 1, 5 do
    total = add(total, i)
end

local function classify(n)
    if n < 0 then
        return "neg"
    elseif n == 0 then
        return "zero"
    end
    return "pos"
end

print("total", total, "class", classify(total))
return total
