use bytecode::opcode::Opcode;

use crate::rng::Rng;
use crate::route::{self, RouteScheme};

pub struct Handler {
    pub op: Opcode,
    pub body: Body,
}

pub enum Body {
    Bin {
        op: &'static str,
    },
    Un {
        prefix: &'static str,
    },
    BinK {
        op: &'static str,
    },
    Assign {
        lhs: &'static str,
        rhs: &'static str,
    },
    Raw(&'static str),
    Crash,
    Branch {
        truthy: bool,
    },
    Variants(&'static [&'static str]),
}

pub const HANDLERS: &[Handler] = &[
    Handler { op: Opcode::Move, body: Body::Variants(&[
        "rs(R, a, rg(R, inst.b))",
        "local _u = rg(R, inst.b)\nrs(R, a, _u)",
    ]) },
    Handler { op: Opcode::LoadK, body: Body::Assign { lhs: "R[a]", rhs: "kget(consts, inst.b + 1, pkey, kc, ktok)" } },
    Handler { op: Opcode::LoadNil, body: Body::Variants(&[
        "for i = 0, inst.b - 1 do\nR[a + i] = nil\nend",
        "for i = a, a + inst.b - 1 do\nR[i] = nil\nend",
        "for i = 0, inst.b - 1 do\nrs(R, a + i, nil)\nend",
    ]) },
    Handler { op: Opcode::LoadBool, body: Body::Assign { lhs: "R[a]", rhs: "inst.b ~= 0" } },
    Handler { op: Opcode::GetGlobal, body: Body::Variants(&[
        "rs(R, a, h_g(kget(consts, inst.b + 1, pkey, kc, ktok)))",
        "local _k = kget(consts, inst.b + 1, pkey, kc, ktok)\nrs(R, a, h_g(_k))",
        "local _k = kget(consts, inst.b + 1, pkey, kc, ktok)\nlocal _v = h_g(_k)\nrs(R, a, _v)",
    ]) },
    Handler { op: Opcode::SetGlobal, body: Body::Variants(&[
        "h_gs(kget(consts, inst.b + 1, pkey, kc, ktok), rg(R, a))",
        "local _k = kget(consts, inst.b + 1, pkey, kc, ktok)\nh_gs(_k, rg(R, a))",
        "local _k = kget(consts, inst.b + 1, pkey, kc, ktok)\nlocal _v = rg(R, a)\nh_gs(_k, _v)",
    ]) },
    Handler { op: Opcode::GetUpval, body: Body::Assign { lhs: "R[a]", rhs: "uvget(upvals[inst.b + 1])" } },
    Handler { op: Opcode::SetUpval, body: Body::Variants(&[
        "uvset(upvals[inst.b + 1], R[a])",
        "local _uv = upvals[inst.b + 1]\nuvset(_uv, R[a])",
        "local _v = rg(R, a)\nuvset(upvals[inst.b + 1], _v)",
    ]) },
    Handler { op: Opcode::NewTable, body: Body::Assign { lhs: "R[a]", rhs: "{}" } },
    Handler { op: Opcode::GetTable, body: Body::Variants(&[
        "local _u = rg(R, inst.b)\nlocal _w = rg(R, inst.c)\nrs(R, a, rg(_u, _w))",
        "local _u = rg(R, inst.b)\nlocal _w = rg(R, inst.c)\nlocal _z = rg(_u, _w)\nrs(R, a, _z)",
        "local _u = rg(R, inst.b)\nlocal _z = rg(_u, rg(R, inst.c))\nrs(R, a, _z)",
        "local _u = rg(R, inst.b)\nlocal _w = rg(R, inst.c)\nlocal _z = rg(_u, _w)\nR[a] = _z",
    ]) },
    Handler { op: Opcode::SetTable, body: Body::Variants(&[
        "local _u = rg(R, a)\nlocal _w = rg(R, inst.b)\nlocal _z = rg(R, inst.c)\nrs(_u, _w, _z)",
        "do\nlocal _u = rg(R, a)\nlocal _w = rg(R, inst.b)\nlocal _z = rg(R, inst.c)\nrs(_u, _w, _z)\nend",
        "local _u = rg(R, a)\nlocal _w = rg(R, inst.b)\nlocal _z = rg(R, inst.c)\n_u[_w] = _z",
    ]) },
    Handler { op: Opcode::SetList, body: Body::Variants(&[
        "local n = inst.b\nif n == 0 then\nn = top - a - 1\nend\nlocal base = inst.c\nlocal t = R[a]\nfor i = 1, n do\nt[base + i - 1] = R[a + i]\nend",
        "local n = inst.b\nif n == 0 then\nn = top - a - 1\nend\nlocal base = inst.c\nlocal t = R[a]\nfor i = 0, n - 1 do\nt[base + i] = R[a + i + 1]\nend",
        "local n = inst.b\nif n == 0 then\nn = top - a - 1\nend\nlocal base = inst.c\nlocal t = R[a]\nfor i = 1, n do\nrs(t, base + i - 1, R[a + i])\nend",
    ]) },
    Handler { op: Opcode::Self_, body: Body::Variants(&[
        "local _u = rg(R, inst.b)\nlocal _m, _s = h_self(_u, kget(consts, inst.c + 1, pkey, kc, ktok))\nrs(R, a + 1, _s)\nrs(R, a, _m)",
        "local _u = rg(R, inst.b)\nlocal _k = kget(consts, inst.c + 1, pkey, kc, ktok)\nlocal _m, _s = h_self(_u, _k)\nrs(R, a + 1, _s)\nrs(R, a, _m)",
        "local _u = rg(R, inst.b)\nlocal _k = kget(consts, inst.c + 1, pkey, kc, ktok)\nlocal _m, _s = h_self(_u, _k)\nR[a + 1] = _s\nR[a] = _m",
    ]) },
    Handler { op: Opcode::Add, body: Body::Bin { op: "+" } },
    Handler { op: Opcode::Sub, body: Body::Bin { op: "-" } },
    Handler { op: Opcode::Mul, body: Body::Bin { op: "*" } },
    Handler { op: Opcode::Div, body: Body::Bin { op: "/" } },
    Handler { op: Opcode::Mod, body: Body::Bin { op: "%" } },
    Handler { op: Opcode::Pow, body: Body::Bin { op: "^" } },
    Handler { op: Opcode::IDiv, body: Body::Bin { op: "//" } },
    Handler { op: Opcode::Concat, body: Body::Bin { op: ".." } },
    Handler { op: Opcode::Neg, body: Body::Un { prefix: "-" } },
    Handler { op: Opcode::Not, body: Body::Un { prefix: "not " } },
    Handler { op: Opcode::Len, body: Body::Un { prefix: "#" } },
    Handler { op: Opcode::Eq, body: Body::Bin { op: "==" } },
    Handler { op: Opcode::Ne, body: Body::Bin { op: "~=" } },
    Handler { op: Opcode::Lt, body: Body::Bin { op: "<" } },
    Handler { op: Opcode::Le, body: Body::Bin { op: "<=" } },
    Handler { op: Opcode::Gt, body: Body::Bin { op: ">" } },
    Handler { op: Opcode::Ge, body: Body::Bin { op: ">=" } },
    Handler { op: Opcode::Jmp, body: Body::Assign { lhs: "pc", rhs: "pc + a" } },
    Handler { op: Opcode::JmpIf, body: Body::Branch { truthy: true } },
    Handler { op: Opcode::JmpIfNot, body: Body::Branch { truthy: false } },
    Handler { op: Opcode::Call, body: Body::Variants(&[
        "local f = R[a]\nlocal b = inst.b\nlocal argTop\nif b == 0 then\nargTop = top\nelse\nargTop = a + b\nend\nlocal c = inst.c\nif c == 2 then\nR[a] = f(unpack(R, a + 1, argTop - 1))\nelseif c == 1 then\nf(unpack(R, a + 1, argTop - 1))\nelse\nlocal results = pack(f(unpack(R, a + 1, argTop - 1)))\nif c == 0 then\nfor i = 1, results.n do\nR[a + i - 1] = results[i]\nend\ntop = a + results.n\nelse\nfor i = 1, c - 1 do\nR[a + i - 1] = results[i]\nend\nend\nend",
        "local f = R[a]\nlocal b = inst.b\nlocal argTop\nif b == 0 then\nargTop = top\nelse\nargTop = a + b\nend\nlocal c = inst.c\nif c == 2 then\nR[a] = f(unpack(R, a + 1, argTop - 1))\nelseif c == 1 then\nf(unpack(R, a + 1, argTop - 1))\nelse\nlocal results = pack(f(unpack(R, a + 1, argTop - 1)))\nif c == 0 then\nfor i = 0, results.n - 1 do\nR[a + i] = results[i + 1]\nend\ntop = a + results.n\nelse\nfor i = 0, c - 2 do\nR[a + i] = results[i + 1]\nend\nend\nend",
        "local f = R[a]\nlocal b = inst.b\nlocal argTop\nif b == 0 then\nargTop = top\nelse\nargTop = a + b\nend\nlocal c = inst.c\nif c == 2 then\nrs(R, a, f(unpack(R, a + 1, argTop - 1)))\nelseif c == 1 then\nf(unpack(R, a + 1, argTop - 1))\nelse\nlocal results = pack(f(unpack(R, a + 1, argTop - 1)))\nif c == 0 then\nfor i = 1, results.n do\nrs(R, a + i - 1, results[i])\nend\ntop = a + results.n\nelse\nfor i = 1, c - 1 do\nrs(R, a + i - 1, results[i])\nend\nend\nend",
    ]) },
    Handler { op: Opcode::Return, body: Body::Variants(&[
        "local b = inst.b\nif b == 0 then\nreturn unpack(R, a, top - 1)\nelse\nreturn unpack(R, a, a + b - 2)\nend",
        "local b = inst.b\nlocal _hi\nif b == 0 then\n_hi = top - 1\nelse\n_hi = a + b - 2\nend\nreturn unpack(R, a, _hi)",
        "local b = inst.b\nif b == 0 then\nreturn unpack(R, a, top - 1)\nend\nreturn unpack(R, a, a + b - 2)",
        "local b = inst.b\nreturn unpack(R, a, b == 0 and top - 1 or a + b - 2)",
        "local b = inst.b\nlocal _hi\nif b == 0 then\n_hi = top - 1\nelse\n_hi = a + b - 2\nend\nlocal _p = pack(unpack(R, a, _hi))\nreturn unpack(_p, 1, _p.n)",
        "local b = inst.b\nif b == 1 then\nreturn\nelseif b == 0 then\nreturn unpack(R, a, top - 1)\nend\nreturn unpack(R, a, a + b - 2)",
    ]) },
    Handler { op: Opcode::Vararg, body: Body::Variants(&[
        "local b = inst.b\nif b == 0 then\nfor i = 1, nvar do\nR[a + i - 1] = varargs[i]\nend\ntop = a + nvar\nelse\nfor i = 1, b - 1 do\nR[a + i - 1] = varargs and varargs[i] or nil\nend\nend",
        "local b = inst.b\nif b == 0 then\nfor i = 0, nvar - 1 do\nR[a + i] = varargs[i + 1]\nend\ntop = a + nvar\nelse\nfor i = 0, b - 2 do\nR[a + i] = varargs and varargs[i + 1] or nil\nend\nend",
        "local b = inst.b\nif b == 0 then\nfor i = 0, nvar - 1 do\nrs(R, a + i, varargs[i + 1])\nend\ntop = a + nvar\nelse\nfor i = 0, b - 2 do\nrs(R, a + i, varargs and varargs[i + 1] or nil)\nend\nend",
    ]) },
    Handler { op: Opcode::Closure, body: Body::Variants(&[
        "local child = protos[inst.b + 1]\nlocal cu = {}\nlocal descs = child[3]\nfor i = 1, #descs do\nlocal d = descs[i]\nif d[KIS] then\nlocal reg = d[KIX]\nlocal uv = openuv[reg]\nif not uv then\nuv = { [KOPEN] = true, [KR] = R, [KIDX] = reg }\nopenuv[reg] = uv\nend\ncu[i] = uv\nelse\ncu[i] = upvals[d[KIX] + 1]\nend\nend\nchild[20] = actTicket(proto[20], child[5])\nR[a] = makeClosure(child, cu)",
        "local child = protos[inst.b + 1]\nlocal cu = {}\nlocal descs = child[3]\nfor i = 1, #descs do\nlocal d = descs[i]\nif d[KIS] then\nlocal reg = d[KIX]\nlocal uv = openuv[reg]\nif not uv then\nuv = { [KOPEN] = true, [KR] = R, [KIDX] = reg }\nopenuv[reg] = uv\nend\ncu[i] = uv\nelse\ncu[i] = upvals[d[KIX] + 1]\nend\nend\nchild[20] = actTicket(proto[20], child[5])\nlocal _c = makeClosure(child, cu)\nR[a] = _c",
        "local child = protos[inst.b + 1]\nlocal cu = {}\nlocal descs = child[3]\nfor i = 1, #descs do\nlocal d = descs[i]\nif not d[KIS] then\ncu[i] = upvals[d[KIX] + 1]\nelse\nlocal reg = d[KIX]\nlocal uv = openuv[reg]\nif not uv then\nuv = { [KOPEN] = true, [KR] = R, [KIDX] = reg }\nopenuv[reg] = uv\nend\ncu[i] = uv\nend\nend\nchild[20] = actTicket(proto[20], child[5])\nrs(R, a, makeClosure(child, cu))",
    ]) },
    Handler { op: Opcode::ForPrep, body: Body::Variants(&[
        "R[a] = R[a] - R[a + 2]\npc = pc + inst.b",
        "local _u = R[a] - R[a + 2]\nR[a] = _u\npc = pc + inst.b",
        "R[a] = R[a] - R[a + 2]\nlocal _p = pc + inst.b\npc = _p",
        "local _u = R[a] - R[a + 2]\nrs(R, a, _u)\npc = pc + inst.b",
    ]) },
    Handler { op: Opcode::ForLoop, body: Body::Variants(&[
        "local step = R[a + 2]\nlocal idx = R[a] + step\nR[a] = idx\nlocal limit = R[a + 1]\nif (step >= 0 and idx <= limit) or (step < 0 and idx >= limit) then\nR[a + 3] = idx\npc = pc + inst.b\nend",
        "local step = R[a + 2]\nlocal idx = R[a] + step\nR[a] = idx\nlocal limit = R[a + 1]\nlocal _g = (step >= 0 and idx <= limit) or (step < 0 and idx >= limit)\nif _g then\nR[a + 3] = idx\npc = pc + inst.b\nend",
        "local step = R[a + 2]\nlocal idx = R[a] + step\nR[a] = idx\nlocal limit = R[a + 1]\nlocal _g = (step >= 0 and idx <= limit) or (step < 0 and idx >= limit)\nif _g then\nR[a + 3] = idx\nlocal _p = pc + inst.b\npc = _p\nend",
        "local step = R[a + 2]\nlocal idx = R[a] + step\nrs(R, a, idx)\nlocal limit = R[a + 1]\nif (step >= 0 and idx <= limit) or (step < 0 and idx >= limit) then\nrs(R, a + 3, idx)\npc = pc + inst.b\nend",
    ]) },
    Handler { op: Opcode::TForCall, body: Body::Variants(&[
        "local f = R[a]\nif type(f) == \"table\" then\nlocal _mt = getmetatable(f)\nlocal _it = _mt and _mt.__iter\nif _it ~= nil then\nlocal _nf, _ns, _nc = _it(f)\nR[a] = _nf\nR[a + 1] = _ns\nR[a + 2] = _nc\nf = _nf\nelseif not (_mt and _mt.__call) then\nR[a + 1] = f\nR[a] = next\nf = next\nend\nend\nlocal _b = inst.b\nif _b == 2 then\nR[a + 3], R[a + 4] = f(R[a + 1], R[a + 2])\nelseif _b == 1 then\nR[a + 3] = f(R[a + 1], R[a + 2])\nelseif _b == 3 then\nR[a + 3], R[a + 4], R[a + 5] = f(R[a + 1], R[a + 2])\nelse\nlocal results = pack(f(R[a + 1], R[a + 2]))\nfor i = 1, _b do\nR[a + 3 + i - 1] = results[i]\nend\nend",
        "local f = R[a]\nif type(f) == \"table\" then\nlocal _mt = getmetatable(f)\nlocal _it = _mt and _mt.__iter\nif _it ~= nil then\nlocal _nf, _ns, _nc = _it(f)\nR[a] = _nf\nR[a + 1] = _ns\nR[a + 2] = _nc\nf = _nf\nelseif not (_mt and _mt.__call) then\nR[a + 1] = f\nR[a] = next\nf = next\nend\nend\nlocal _b = inst.b\nif _b == 1 then\nR[a + 3] = f(R[a + 1], R[a + 2])\nelseif _b == 2 then\nlocal _r1, _r2 = f(R[a + 1], R[a + 2])\nR[a + 3] = _r1\nR[a + 4] = _r2\nelseif _b == 3 then\nlocal _r1, _r2, _r3 = f(R[a + 1], R[a + 2])\nR[a + 3] = _r1\nR[a + 4] = _r2\nR[a + 5] = _r3\nelse\nlocal results = pack(f(R[a + 1], R[a + 2]))\nfor i = 0, _b - 1 do\nR[a + 3 + i] = results[i + 1]\nend\nend",
        "local f = R[a]\nif type(f) == \"table\" then\nlocal _mt = getmetatable(f)\nlocal _it = _mt and _mt.__iter\nif _it ~= nil then\nlocal _nf, _ns, _nc = _it(f)\nR[a] = _nf\nR[a + 1] = _ns\nR[a + 2] = _nc\nf = _nf\nelseif not (_mt and _mt.__call) then\nR[a + 1] = f\nR[a] = next\nf = next\nend\nend\nlocal _x = R[a + 1]\nlocal _y = R[a + 2]\nlocal _b = inst.b\nif _b == 2 then\nR[a + 3], R[a + 4] = f(_x, _y)\nelseif _b == 1 then\nR[a + 3] = f(_x, _y)\nelseif _b == 3 then\nR[a + 3], R[a + 4], R[a + 5] = f(_x, _y)\nelse\nlocal results = pack(f(_x, _y))\nfor i = 1, _b do\nrs(R, a + 3 + i - 1, results[i])\nend\nend",
    ]) },
    Handler { op: Opcode::TForLoop, body: Body::Variants(&[
        "if R[a + 3] ~= nil then\nR[a + 2] = R[a + 3]\npc = pc + inst.b\nend",
        "local _v = R[a + 3]\nif _v ~= nil then\nR[a + 2] = _v\npc = pc + inst.b\nend",
        "local _v = R[a + 3]\nif _v ~= nil then\nR[a + 2] = _v\nlocal _p = pc + inst.b\npc = _p\nend",
        "local _v = R[a + 3]\nif _v ~= nil then\nrs(R, a + 2, _v)\npc = pc + inst.b\nend",
    ]) },
    Handler { op: Opcode::Close, body: Body::Variants(&[
        "for reg, uv in pairs(openuv) do\nif reg >= a then\nuv[KV] = R[reg]\nuv[KOPEN] = false\nuv[KR] = nil\nopenuv[reg] = nil\nend\nend",
        "for reg, uv in pairs(openuv) do\nif reg >= a then\nlocal _v = R[reg]\nuv[KV] = _v\nuv[KOPEN] = false\nuv[KR] = nil\nopenuv[reg] = nil\nend\nend",
        "for reg, uv in pairs(openuv) do\nif reg >= a then\nuv[KV] = rg(R, reg)\nuv[KOPEN] = false\nuv[KR] = nil\nopenuv[reg] = nil\nend\nend",
    ]) },
    Handler { op: Opcode::AddK, body: Body::BinK { op: "+" } },
    Handler { op: Opcode::SubK, body: Body::BinK { op: "-" } },
    Handler { op: Opcode::MulK, body: Body::BinK { op: "*" } },
    Handler { op: Opcode::DivK, body: Body::BinK { op: "/" } },
    Handler { op: Opcode::ModK, body: Body::BinK { op: "%" } },
    Handler { op: Opcode::PowK, body: Body::BinK { op: "^" } },
    Handler { op: Opcode::IDivK, body: Body::BinK { op: "//" } },
    Handler { op: Opcode::ConcatK, body: Body::BinK { op: ".." } },
    Handler { op: Opcode::EqK, body: Body::BinK { op: "==" } },
    Handler { op: Opcode::NeK, body: Body::BinK { op: "~=" } },
    Handler { op: Opcode::LtK, body: Body::BinK { op: "<" } },
    Handler { op: Opcode::LeK, body: Body::BinK { op: "<=" } },
    Handler { op: Opcode::GtK, body: Body::BinK { op: ">" } },
    Handler { op: Opcode::GeK, body: Body::BinK { op: ">=" } },
    Handler { op: Opcode::LoadNative, body: Body::Assign { lhs: "R[a]", rhs: "NATIVE[inst.b + 1]" } },
    Handler { op: Opcode::Crash, body: Body::Crash },
    Handler { op: Opcode::EncFunc, body: Body::Assign { lhs: "R[a]", rhs: "makeEncWrapper(BLOBS[inst.b + 1], R[inst.c], inst.b)" } },
    Handler { op: Opcode::GetGlobalI, body: Body::Variants(&[
        "rs(R, a, h_g(icat(inst.b)))",
        "local _k = icat(inst.b)\nrs(R, a, h_g(_k))",
        "local _k = icat(inst.b)\nlocal _v = h_g(_k)\nrs(R, a, _v)",
    ]) },
    Handler { op: Opcode::SelfI, body: Body::Variants(&[
        "local _u = rg(R, inst.b)\nlocal _m, _s = h_self(_u, icat(inst.c))\nrs(R, a + 1, _s)\nrs(R, a, _m)",
        "local _u = rg(R, inst.b)\nlocal _k = icat(inst.c)\nlocal _m, _s = h_self(_u, _k)\nrs(R, a + 1, _s)\nrs(R, a, _m)",
        "local _u = rg(R, inst.b)\nlocal _k = icat(inst.c)\nlocal _m, _s = h_self(_u, _k)\nR[a + 1] = _s\nR[a] = _m",
    ]) },

    Handler { op: Opcode::Pad, body: Body::Raw("do end") },
    Handler { op: Opcode::BStateStep, body: Body::Raw("kc[-4] = bxor(fmix(kc[-4]), a % 0x100000000)") },
    Handler { op: Opcode::MApplyReset, body: Body::Raw("sel = (inst.b * 1000003) % 0x100000000\nlocal _o = sel % 3\nlocal _u = rg(R, a)\nlocal _k = kget(consts, inst.c + 1, pkey, kc, ktok)\nif _o == 0 then\nrs(R, a, _u + _k)\nelseif _o == 1 then\nrs(R, a, _u - _k)\nelse\nrs(R, a, _u * _k)\nend") },
    Handler { op: Opcode::MApplyFold, body: Body::Raw("sel = (sel * 1000003 + inst.b) % 0x100000000\nlocal _o = sel % 3\nlocal _u = rg(R, a)\nlocal _k = kget(consts, inst.c + 1, pkey, kc, ktok)\nif _o == 0 then\nrs(R, a, _u + _k)\nelseif _o == 1 then\nrs(R, a, _u - _k)\nelse\nrs(R, a, _u * _k)\nend") },
];

pub fn mutate(body: &Body, rng: &mut Rng, scheme: &RouteScheme, _uh: bool) -> String {
    match body {
        Body::Bin { op, .. } => mutate_bin(op, rng, scheme),
        Body::Un { prefix } => mutate_un(prefix, rng, scheme),
        Body::BinK { op } => mutate_bink(op, rng, scheme),
        Body::Assign { lhs, rhs } => mutate_assign(lhs, rhs, rng),
        Body::Raw(s) => s.to_string(),
        Body::Crash => mutate_crash(),
        Body::Branch { truthy } => mutate_branch(*truthy, rng, scheme),
        Body::Variants(vs) => {
            let raw = rng.below(vs.len() as u64);
            vs[raw as usize].to_string()
        }
    }
}

fn mutate_crash() -> String {
    crate::dispatch::BAD_OP.to_string()
}

fn mutate_bink(op: &str, rng: &mut Rng, scheme: &RouteScheme) -> String {
    let (h, m) = scheme.route(op);
    let k = "kget(consts, inst.c + 1, pkey, kc, ktok)";
    let a = "rg(R, a)";
    match rng.below(4) {
        0 => format!("local _u = {a}\nlocal _k = {k}\nrs(R, a, {h}({m}, _u, _k))"),
        1 => format!("local _k = {k}\nrs(R, a, {h}({m}, {a}, _k))"),
        2 => format!("local _u = {a}\nrs(R, a, {h}({m}, _u, {k}))"),
        _ => format!("local _u = {a}\nlocal _k = {k}\nlocal _t = {h}({m}, _u, _k)\nrs(R, a, _t)"),
    }
}

fn mutate_bin(op: &str, rng: &mut Rng, scheme: &RouteScheme) -> String {
    let (h, m) = scheme.route(op);
    let l = "rg(R, inst.b)";
    let r = "rg(R, inst.c)";
    match rng.below(5) {
        0 => format!("rs(R, a, {h}({m}, {l}, {r}))"),
        1 => format!("local _u = {l}\nlocal _v = {r}\nrs(R, a, {h}({m}, _u, _v))"),
        2 => format!("local _t = {h}({m}, {l}, {r})\nrs(R, a, _t)"),
        3 => format!("local _u = {l}\nlocal _v = {r}\nlocal _t = {h}({m}, _u, _v)\nrs(R, a, _t)"),

        _ => format!("local _u = {l}\nrs(R, a, {h}({m}, _u, {r}))"),
    }
}

fn mutate_un(prefix: &str, rng: &mut Rng, scheme: &RouteScheme) -> String {
    let (h, m) = scheme.route(route::un_key(prefix));
    let x = "rg(R, inst.b)";
    match rng.below(3) {
        0 => format!("rs(R, a, {h}({m}, {x}))"),
        1 => format!("local _u = {x}\nrs(R, a, {h}({m}, _u))"),
        _ => format!("local _t = {h}({m}, {x})\nrs(R, a, _t)"),
    }
}

fn mutate_branch(truthy: bool, rng: &mut Rng, scheme: &RouteScheme) -> String {
    let (h, m) = scheme.route(if truthy { "truthy" } else { "falsy" });
    match rng.below(3) {
        0 => format!("if {h}({m}, rg(R, a)) then\npc = pc + inst.b\nend"),
        1 => format!("local _u = rg(R, a)\nif {h}({m}, _u) then\npc = pc + inst.b\nend"),
        _ => format!(
            "local _u = rg(R, a)\nlocal _p = pc + inst.b\nif {h}({m}, _u) then\npc = _p\nend"
        ),
    }
}

fn mutate_assign(lhs: &str, rhs: &str, rng: &mut Rng) -> String {
    if lhs == "R[a]" {
        match rng.below(3) {
            0 => format!("rs(R, a, {rhs})"),
            1 => format!("local _t = {rhs}\nrs(R, a, _t)"),
            _ => format!("local _t = {rhs}\nR[a] = _t"),
        }
    } else if rng.below(2) == 0 {
        format!("{lhs} = {rhs}")
    } else {
        format!("local _t = {rhs}\n{lhs} = _t")
    }
}

pub fn flat_state_eq_body(rng: &mut Rng, _scheme: &RouteScheme, prof: bool) -> String {
    let nz = match rng.below(3) {
        0 => "_v == nil",
        1 => "not _v",
        _ => "_v == nil",
    };
    let form = match rng.below(2) {
        0 => "dead or type(_v) ~= \"number\" or _v < 0 or _v >= 0x100000000 or _v % 1 ~= 0",
        _ => "dead or type(_v) ~= \"number\" or _v % 1 ~= 0 or _v < 0 or _v >= 0x100000000",
    };
    let cmp = match rng.below(2) {
        0 => "rs(R, inst.ops[4], rg(R, inst.ops[5]) == _v)",
        _ => "rs(R, inst.ops[4], _v == rg(R, inst.ops[5]))",
    };

    let (pn, pm, ph) = if prof {
        (
            "PROF_FSE_N = PROF_FSE_N + 1\n",
            "PROF_FSE_MISS = PROF_FSE_MISS + 1\n",
            "else\nPROF_FSE_HIT = PROF_FSE_HIT + 1\n",
        )
    } else {
        ("", "", "")
    };
    format!(
        "do\nlocal _ci = inst.ops[2] + 1\nlocal _v = fbm[_ci]\n{pn}if {nz} then\n{pm}_v = kget(consts, _ci, pkey, kc, ktok)\nif {form} then\ndead = true\n_v = 0\nelse\nfbm[_ci] = _v\nend\n{ph}end\n{cmp}\nend\n"
    )
}

pub fn super_body(op: Opcode, rng: &mut Rng, scheme: &RouteScheme, uh: bool) -> String {
    let subs = bytecode::superop::sub_ops(op).expect("super_body called on a non-super op");
    let mut out = String::new();
    for (k, &sub) in subs.iter().enumerate() {
        let h = HANDLERS
            .iter()
            .find(|h| h.op == sub)
            .expect("sub-op has no handler");
        let body = mutate(&h.body, rng, scheme, uh)
            .replace("inst.b", "b")
            .replace("inst.c", "c");
        let base = 3 * k;
        out.push_str(&format!(
            "do\nlocal a, b, c = inst.ops[{}], inst.ops[{}], inst.ops[{}]\n{body}\nend\n",
            base + 1,
            base + 2,
            base + 3
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytecode::opcode::ALL;

    #[test]
    fn model_covers_every_opcode() {
        assert_eq!(
            HANDLERS.len()
                + bytecode::superop::CATALOGUE.len()
                + bytecode::opcode::SYNONYMS.len()
                + 1,
            ALL.len()
        );
        for (op, _) in ALL {
            if bytecode::opcode::is_gensuper(*op) {
                continue;
            }
            if let Some(subs) = bytecode::superop::sub_ops(*op) {
                for s in subs {
                    assert!(
                        HANDLERS.iter().any(|h| h.op == *s),
                        "super sub {s:?} has no handler"
                    );
                }
            } else if let Some((_, base)) = bytecode::opcode::SYNONYMS.iter().find(|(s, _)| s == op)
            {
                assert!(
                    HANDLERS.iter().any(|h| h.op == *base),
                    "synonym base {base:?} has no handler"
                );
            } else {
                assert!(
                    HANDLERS.iter().any(|h| h.op == *op),
                    "missing handler for {op:?}"
                );
            }
        }
    }

    #[test]
    fn mutation_is_deterministic_per_seed() {
        let scheme = RouteScheme::new(9, 0);
        for h in HANDLERS {
            assert_eq!(
                mutate(&h.body, &mut Rng::new(9), &scheme, false),
                mutate(&h.body, &mut Rng::new(9), &scheme, false)
            );
        }
    }

    #[test]
    fn introduced_temps_avoid_scope_and_reserved_names() {
        let forbidden = [" a ", " op ", " t ", " b ", " c ", " n ", " f ", " R "];
        for h in HANDLERS {
            for seed in 0..16u64 {
                let scheme = RouteScheme::new(seed, 0);
                let out = mutate(&h.body, &mut Rng::new(seed), &scheme, false);
                for decl in out.lines().filter(|l| l.starts_with("local _")) {
                    assert!(
                        forbidden.iter().all(|f| !decl.contains(f)),
                        "`{decl}` hits a reserved name"
                    );
                }
            }
        }
    }

    fn abstract_skeleton(s: &str) -> String {
        let b = s.as_bytes();
        let mut out = String::new();
        let mut i = 0;
        while i < b.len() {
            let c = b[i];
            if c.is_ascii_digit() {
                while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'.' || b[i] == b'_')
                {
                    i += 1;
                }
                out.push('N');
            } else if c.is_ascii_alphabetic() || c == b'_' {
                while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                    i += 1;
                }
                out.push('I');
            } else if c.is_ascii_whitespace() {
                i += 1;
            } else {
                out.push(c as char);
                i += 1;
            }
        }
        out
    }

    #[test]
    fn handlers_emit_multiple_normalized_skeletons_across_seeds() {
        let deferred = [
            Opcode::SetList,
            Opcode::Call,
            Opcode::Return,
            Opcode::Vararg,
            Opcode::Closure,
            Opcode::ForLoop,
            Opcode::TForCall,
            Opcode::TForLoop,
            Opcode::Close,
        ];
        let mut multi = 0;
        let mut deferred_multi = 0;
        for h in HANDLERS {
            let mut shapes = std::collections::HashSet::new();
            for seed in 0..64u64 {
                let scheme = RouteScheme::new(seed, 0);
                shapes.insert(abstract_skeleton(&mutate(
                    &h.body,
                    &mut Rng::new(seed),
                    &scheme,
                    false,
                )));
            }
            if shapes.len() >= 2 {
                multi += 1;
                if deferred.contains(&h.op) {
                    deferred_multi += 1;
                }
            }
        }
        assert!(
            multi >= 34,
            "handler bodies must emit multiple abstracted skeletons across seeds: only {multi} of {}",
            HANDLERS.len()
        );
        assert!(
            deferred_multi >= 9,
            "the previously-deferred complex handlers must now emit multiple skeletons: only {deferred_multi} of {}",
            deferred.len()
        );
    }

    const COMPLEX: [Opcode; 13] = [
        Opcode::Call,
        Opcode::Return,
        Opcode::Vararg,
        Opcode::Closure,
        Opcode::SetList,
        Opcode::ForPrep,
        Opcode::ForLoop,
        Opcode::TForCall,
        Opcode::TForLoop,
        Opcode::Close,
        Opcode::GetTable,
        Opcode::SetTable,
        Opcode::Self_,
    ];

    fn shapes_across_seeds(body: &Body, n: u64) -> Vec<String> {
        (0..n)
            .map(|s| {
                abstract_skeleton(&mutate(
                    body,
                    &mut Rng::new(s),
                    &RouteScheme::new(s, 0),
                    false,
                ))
            })
            .collect()
    }

    #[test]
    fn no_stable_logical_opcode_to_handler_skeleton_association() {
        let per: Vec<(Opcode, Vec<String>)> = HANDLERS
            .iter()
            .map(|h| (h.op, shapes_across_seeds(&h.body, 32)))
            .collect();
        for op in COMPLEX {
            let shapes = &per.iter().find(|(o, _)| *o == op).unwrap().1;
            let uniq: std::collections::HashSet<&String> = shapes.iter().collect();
            assert!(
                uniq.len() >= 2,
                "{op:?} collapses to a single handler skeleton across builds"
            );
            let dominant = uniq
                .iter()
                .map(|u| shapes.iter().filter(|s| s.as_str() == u.as_str()).count())
                .max()
                .unwrap();
            assert!(
                dominant * 10 < shapes.len() * 8,
                "{op:?} has a dominant skeleton ({dominant}/{} seeds) — a reliable static fingerprint",
                shapes.len()
            );
        }

        let total: std::collections::HashSet<&String> =
            per.iter().flat_map(|(_, s)| s.iter()).collect();
        let summed: usize = per
            .iter()
            .map(|(_, s)| s.iter().collect::<std::collections::HashSet<_>>().len())
            .sum();
        assert!(
            total.len() * 3 < summed * 2,
            "handler skeletons must overlap across opcodes ({} distinct vs {summed} summed)",
            total.len()
        );
    }

    fn declared_locals(body: &str) -> Vec<String> {
        let mut names = Vec::new();
        for line in body.lines() {
            if let Some(rest) = line.trim_start().strip_prefix("local ") {
                let decl = rest.split('=').next().unwrap_or(rest);
                for n in decl.split(',') {
                    let n = n.trim();
                    if !n.is_empty() && n.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_') {
                        names.push(n.to_string());
                    }
                }
            }
        }
        names
    }

    fn word_count(body: &str, name: &str) -> usize {
        let (b, nb) = (body.as_bytes(), name.as_bytes());
        let (mut count, mut i) = (0usize, 0usize);
        while i + nb.len() <= b.len() {
            if &b[i..i + nb.len()] == nb {
                let before = i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_');
                let a = i + nb.len();
                let after = a >= b.len() || !(b[a].is_ascii_alphanumeric() || b[a] == b'_');
                if before && after {
                    count += 1;
                    i = a;
                    continue;
                }
            }
            i += 1;
        }
        count
    }

    #[test]
    fn handler_variants_contain_no_dead_junk() {
        for h in HANDLERS {
            if h.op == Opcode::Pad {
                continue;
            }
            for seed in 0..24u64 {
                let body = mutate(
                    &h.body,
                    &mut Rng::new(seed),
                    &RouteScheme::new(seed, 0),
                    false,
                );
                let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
                assert!(
                    !compact.contains("doend"),
                    "{:?} seed {seed}: empty do-end block",
                    h.op
                );
                assert!(
                    !body.contains("if true") && !body.contains("if false"),
                    "{:?} seed {seed}: constant-condition branch",
                    h.op
                );
                for name in declared_locals(&body) {
                    assert!(
                        word_count(&body, &name) >= 2,
                        "{:?} seed {seed}: local `{name}` is declared but never read (dead)",
                        h.op
                    );
                }
            }
        }
    }

    #[test]
    fn complex_handlers_have_multiple_noncosmetic_skeletons() {
        for op in COMPLEX {
            let body = &HANDLERS.iter().find(|h| h.op == op).unwrap().body;
            let shapes: std::collections::HashSet<String> =
                shapes_across_seeds(body, 48).into_iter().collect();
            assert!(
                shapes.len() >= 3,
                "complex handler {op:?} must emit >= 3 distinct skeletons, got {}",
                shapes.len()
            );
        }
    }
}
