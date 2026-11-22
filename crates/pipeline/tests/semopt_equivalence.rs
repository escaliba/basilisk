use passes::semopt::OptMode;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static N: AtomicU64 = AtomicU64::new(0);

fn find_luau() -> Option<String> {
    for cand in ["luau", "/opt/homebrew/bin/luau", "/usr/local/bin/luau"] {
        if Command::new(cand)
            .arg("--version")
            .output()
            .ok()
            .filter(|o| o.status.success())
            .is_some()
        {
            return Some(cand.into());
        }
    }
    None
}

fn tmp() -> PathBuf {
    std::env::temp_dir().join(format!(
        "basilisk_semopt_{}_{}.luau",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ))
}

fn run_luau(luau: &str, code: &str) -> String {
    let p = tmp();
    std::fs::write(&p, code).unwrap();
    let o = Command::new(luau).arg(&p).output().expect("luau");
    let _ = std::fs::remove_file(&p);
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn optimized(src: &str, mode: OptMode) -> String {
    let mut m = frontend::lower_str(src).expect("lower");
    passes::semopt::optimize(&mut m, mode);
    ir::emit(&m)
}

fn virtualize(src: &str) -> String {
    let s = src.to_string();
    std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(move || {
            pipeline::virtualize_full_prof(
                &s,
                20260809,
                true,
                true,
                true,
                true,
                true,
                false,
                false,
                false,
                false,
                pipeline::SurfaceVolume::Off,
                false,
                pipeline::SensitiveOpts::default(),
                pipeline::TargetProfile::CliTest,
                false,
                false,
            )
            .expect("build")
        })
        .unwrap()
        .join()
        .unwrap()
}

fn corpus() -> Vec<(&'static str, &'static str)> {
    vec![
        ("feature_flags",
         "local DEBUG=false local N=4 local S=3 local t=0 for i=1,N do if DEBUG then t=t+999 end t=t+i*S end print(t)"),
        ("const_in_condition",
         "local MODE=2 local r if MODE==1 then r='a' elseif MODE==2 then r='b' else r='c' end print(r)"),
        ("closure_upvalue_counter",
         "local function mk() local n=0 return function() n=n+1 return n end end local c=mk() print(c(),c(),c())"),
        ("nested_closures",
         "local function outer(x) return function(y) return function(z) return x+y+z end end end print(outer(1)(2)(3))"),
        ("mutable_captured_local",
         "local acc=0 local function add(v) acc=acc+v end add(10) add(5) print(acc)"),
        ("varargs_and_multiret",
         "local function f(...) return select('#',...), (...) end local n,a=f(7,8,9) print(n,a)"),
        ("nil_and_false_are_distinct",
         "local a=nil local b=false print(a==nil, b==false, a==b)"),
        ("nan_and_inf",
         "local inf=1/0 local nan=0/0 print(inf>1e308, nan~=nan)"),
        ("pcall_error",
         "local ok,err=pcall(function() error('boom') end) print(ok, tostring(err):match('boom')~=nil)"),
        ("break_continue",
         "local s=0 for i=1,10 do if i==3 then continue end if i==7 then break end s=s+i end print(s)"),
        ("table_aliasing_mutation",
         "local t={1,2,3} local u=t u[2]=99 print(t[2], #t)"),
        ("metatable_index",
         "local base={x=5} local o=setmetatable({}, {__index=base}) print(o.x, rawget(o,'x'))"),
        ("metamethod_add",
         "local V=setmetatable({n=10},{__add=function(a,b) return a.n+b end}) local k=V+5 print(k)"),
        ("unknown_call_not_reordered",
         "local log={} local function side(x) log[#log+1]=x return x end local a=side(1) local b=side(2) print(a,b,table.concat(log,','))"),
        ("string_build_loop",
         "local r='' for i=1,5 do r=r..i..';' end print(r)"),
        ("reassigned_local",
         "local x=1 x=x+10 x=x*2 print(x)"),
        ("shadowing_across_functions",
         "local N=100 local function f(N) return N*2 end print(f(3), N)"),
        ("numeric_for_with_const_bounds",
         "local LO=2 local HI=5 local s=0 for i=LO,HI do s=s+i end print(s)"),
    ]
}

#[test]
fn optimizer_preserves_semantics_across_modes() {
    let Some(luau) = find_luau() else {
        eprintln!("luau not found; skipping semopt equivalence");
        return;
    };
    for (name, src) in corpus() {
        let plain = run_luau(&luau, src);
        let safe = run_luau(&luau, &optimized(src, OptMode::Safe));
        let exp = run_luau(&luau, &optimized(src, OptMode::Experimental));
        assert_eq!(
            plain, safe,
            "safe optimizer changed observable behavior of `{name}`"
        );
        assert_eq!(
            plain, exp,
            "experimental optimizer changed observable behavior of `{name}`"
        );
    }
}

#[test]
fn optimized_output_virtualizes_equivalently() {
    let Some(luau) = find_luau() else {
        eprintln!("luau not found; skipping semopt virtualize equivalence");
        return;
    };

    for (name, src) in corpus().into_iter().filter(|(n, _)| {
        matches!(
            *n,
            "feature_flags"
                | "closure_upvalue_counter"
                | "varargs_and_multiret"
                | "metamethod_add"
                | "numeric_for_with_const_bounds"
        )
    }) {
        let plain = run_luau(&luau, src);
        let virt_off = run_luau(&luau, &virtualize(src));
        let virt_opt = run_luau(&luau, &virtualize(&optimized(src, OptMode::Safe)));
        assert_eq!(plain, virt_off, "virtualize(off) diverged for `{name}`");
        assert_eq!(
            plain, virt_opt,
            "virtualize(optimized) diverged for `{name}`"
        );
    }
}

#[test]
fn optimizer_reduces_ir_on_opportunity_and_leaves_clean_code_alone() {
    let mut m = frontend::lower_str(
        "local F=false local N=3 local S=2 local t=0 for i=1,N do if F then t=t+9 end t=t+i*S end print(t)",
    )
    .unwrap();
    let r = passes::semopt::optimize(&mut m, OptMode::Safe);
    assert!(
        r.ir_ops_after < r.ir_ops_before,
        "opportunity case must shrink: {r:?}"
    );
    assert!(r.const_propagated > 0 && r.dead_locals_removed > 0);

    let mut c = frontend::lower_str("local t=0 for i=1,10 do t=t+f(i) end print(t)").unwrap();
    let rc = passes::semopt::optimize(&mut c, OptMode::Safe);
    assert!(!rc.changed(), "no false transforms on clean code: {rc:?}");
}

#[test]
fn off_mode_never_touches_the_module() {
    let mut a = frontend::lower_str("local X=5 print(X) if false then dead() end").unwrap();
    let before = a.clone();
    passes::semopt::optimize(&mut a, OptMode::Off);
    assert_eq!(a, before, "off mode must be a no-op");
}
