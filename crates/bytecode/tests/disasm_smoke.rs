#[test]
fn dump_minimal() {
    let module = frontend::lower_str("local x = 1\nprint(x + 2)\n").expect("lower");
    let proto = bytecode::compile(&module).expect("compile");
    println!("\n{}", bytecode::disasm::disassemble(&proto));
}
