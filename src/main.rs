#![allow(unused, dead_code)]
// extern crate structopt;
// extern crate tabwriter;
// extern crate xed_sys as llb; // low-level binding xed

use std::{
    collections::HashMap,
    ffi::{CStr, CString},
    io::{self, Write},
    mem,
    os::raw,
    slice,
};
use structopt::StructOpt;
use tabwriter::TabWriter;
use xed_sys as llb;

use lazy_static::lazy_static;
use maplit::hashmap;

use crate::llb::{xed_iclass_enum_t::*, xed_iform_enum_t::*};

lazy_static! {
    static ref xed_nolock_iform_map: HashMap<llb::xed_iform_enum_t, llb::xed_iform_enum_t> = hashmap! {
        XED_IFORM_ADC_LOCK_MEMb_IMMb_80r2 => XED_IFORM_ADC_MEMb_IMMb_80r2,
        XED_IFORM_ADC_LOCK_MEMv_IMMz => XED_IFORM_ADC_MEMv_IMMz,
        XED_IFORM_ADC_LOCK_MEMb_IMMb_82r2 => XED_IFORM_ADC_MEMb_IMMb_82r2,
        XED_IFORM_ADC_LOCK_MEMv_IMMb => XED_IFORM_ADC_MEMv_IMMb,
        XED_IFORM_ADC_LOCK_MEMb_GPR8 => XED_IFORM_ADC_MEMb_GPR8,
        XED_IFORM_ADC_LOCK_MEMv_GPRv => XED_IFORM_ADC_MEMv_GPRv,
        XED_IFORM_DEC_LOCK_MEMb => XED_IFORM_DEC_MEMb,
        XED_IFORM_DEC_LOCK_MEMv => XED_IFORM_DEC_MEMv,
        XED_IFORM_NOT_LOCK_MEMb => XED_IFORM_NOT_MEMb,
        XED_IFORM_NOT_LOCK_MEMv => XED_IFORM_NOT_MEMv,
        XED_IFORM_SUB_LOCK_MEMb_IMMb_80r5 => XED_IFORM_SUB_MEMb_IMMb_80r5,
        XED_IFORM_SUB_LOCK_MEMv_IMMz => XED_IFORM_SUB_MEMv_IMMz,
        XED_IFORM_SUB_LOCK_MEMb_IMMb_82r5 => XED_IFORM_SUB_MEMb_IMMb_82r5,
        XED_IFORM_SUB_LOCK_MEMv_IMMb => XED_IFORM_SUB_MEMv_IMMb,
        XED_IFORM_SUB_LOCK_MEMb_GPR8 => XED_IFORM_SUB_MEMb_GPR8,
        XED_IFORM_SUB_LOCK_MEMv_GPRv => XED_IFORM_SUB_MEMv_GPRv,
        XED_IFORM_BTC_LOCK_MEMv_IMMb => XED_IFORM_BTC_MEMv_IMMb,
        XED_IFORM_BTC_LOCK_MEMv_GPRv => XED_IFORM_BTC_MEMv_GPRv,
        XED_IFORM_AND_LOCK_MEMb_IMMb_80r4 => XED_IFORM_AND_MEMb_IMMb_80r4,
        XED_IFORM_AND_LOCK_MEMv_IMMz => XED_IFORM_AND_MEMv_IMMz,
        XED_IFORM_AND_LOCK_MEMb_IMMb_82r4 => XED_IFORM_AND_MEMb_IMMb_82r4,
        XED_IFORM_AND_LOCK_MEMv_IMMb => XED_IFORM_AND_MEMv_IMMb,
        XED_IFORM_AND_LOCK_MEMb_GPR8 => XED_IFORM_AND_MEMb_GPR8,
        XED_IFORM_AND_LOCK_MEMv_GPRv => XED_IFORM_AND_MEMv_GPRv,
        XED_IFORM_CMPXCHG_LOCK_MEMb_GPR8 => XED_IFORM_CMPXCHG_MEMb_GPR8,
        XED_IFORM_CMPXCHG_LOCK_MEMv_GPRv => XED_IFORM_CMPXCHG_MEMv_GPRv,
        XED_IFORM_INC_LOCK_MEMb => XED_IFORM_INC_MEMb,
        XED_IFORM_INC_LOCK_MEMv => XED_IFORM_INC_MEMv,
        XED_IFORM_OR_LOCK_MEMb_IMMb_80r1 => XED_IFORM_OR_MEMb_IMMb_80r1,
        XED_IFORM_OR_LOCK_MEMv_IMMz => XED_IFORM_OR_MEMv_IMMz,
        XED_IFORM_OR_LOCK_MEMb_IMMb_82r1 => XED_IFORM_OR_MEMb_IMMb_82r1,
        XED_IFORM_OR_LOCK_MEMv_IMMb => XED_IFORM_OR_MEMv_IMMb,
        XED_IFORM_OR_LOCK_MEMb_GPR8 => XED_IFORM_OR_MEMb_GPR8,
        XED_IFORM_OR_LOCK_MEMv_GPRv => XED_IFORM_OR_MEMv_GPRv,
        XED_IFORM_XADD_LOCK_MEMb_GPR8 => XED_IFORM_XADD_MEMb_GPR8,
        XED_IFORM_XADD_LOCK_MEMv_GPRv => XED_IFORM_XADD_MEMv_GPRv,
        XED_IFORM_ADD_LOCK_MEMb_IMMb_80r0 => XED_IFORM_ADD_MEMb_IMMb_80r0,
        XED_IFORM_ADD_LOCK_MEMv_IMMz => XED_IFORM_ADD_MEMv_IMMz,
        XED_IFORM_ADD_LOCK_MEMb_IMMb_82r0 => XED_IFORM_ADD_MEMb_IMMb_82r0,
        XED_IFORM_ADD_LOCK_MEMv_IMMb => XED_IFORM_ADD_MEMv_IMMb,
        XED_IFORM_ADD_LOCK_MEMb_GPR8 => XED_IFORM_ADD_MEMb_GPR8,
        XED_IFORM_ADD_LOCK_MEMv_GPRv => XED_IFORM_ADD_MEMv_GPRv,
        XED_IFORM_SBB_LOCK_MEMb_IMMb_80r3 => XED_IFORM_SBB_MEMb_IMMb_80r3,
        XED_IFORM_SBB_LOCK_MEMv_IMMz => XED_IFORM_SBB_MEMv_IMMz,
        XED_IFORM_SBB_LOCK_MEMb_IMMb_82r3 => XED_IFORM_SBB_MEMb_IMMb_82r3,
        XED_IFORM_SBB_LOCK_MEMv_IMMb => XED_IFORM_SBB_MEMv_IMMb,
        XED_IFORM_SBB_LOCK_MEMb_GPR8 => XED_IFORM_SBB_MEMb_GPR8,
        XED_IFORM_SBB_LOCK_MEMv_GPRv => XED_IFORM_SBB_MEMv_GPRv,
        XED_IFORM_BTS_LOCK_MEMv_IMMb => XED_IFORM_BTS_MEMv_IMMb,
        XED_IFORM_BTS_LOCK_MEMv_GPRv => XED_IFORM_BTS_MEMv_GPRv,
        XED_IFORM_XOR_LOCK_MEMb_IMMb_80r6 => XED_IFORM_XOR_MEMb_IMMb_80r6,
        XED_IFORM_XOR_LOCK_MEMv_IMMz => XED_IFORM_XOR_MEMv_IMMz,
        XED_IFORM_XOR_LOCK_MEMb_IMMb_82r6 => XED_IFORM_XOR_MEMb_IMMb_82r6,
        XED_IFORM_XOR_LOCK_MEMv_IMMb => XED_IFORM_XOR_MEMv_IMMb,
        XED_IFORM_XOR_LOCK_MEMb_GPR8 => XED_IFORM_XOR_MEMb_GPR8,
        XED_IFORM_XOR_LOCK_MEMv_GPRv => XED_IFORM_XOR_MEMv_GPRv,
        XED_IFORM_BTR_LOCK_MEMv_IMMb => XED_IFORM_BTR_MEMv_IMMb,
        XED_IFORM_BTR_LOCK_MEMv_GPRv => XED_IFORM_BTR_MEMv_GPRv,
        XED_IFORM_CMPXCHG8B_LOCK_MEMq => XED_IFORM_CMPXCHG8B_MEMq,
        XED_IFORM_CMPXCHG8B_LOCK_MEMq => XED_IFORM_CMPXCHG8B_MEMq,
        XED_IFORM_CMPXCHG16B_LOCK_MEMdq => XED_IFORM_CMPXCHG16B_MEMdq,
        XED_IFORM_NEG_LOCK_MEMb => XED_IFORM_NEG_MEMb,
        XED_IFORM_NEG_LOCK_MEMv => XED_IFORM_NEG_MEMv,
    };
}

// use self::llb::*;

macro_rules! ref_to_raw_pointer {
    ($ref_v:expr) => {
        $ref_v as *const _
    };
}

macro_rules! ref_to_mut_raw_pointer {
    ($ref_v:expr) => {
        $ref_v as *mut _
    };
}

macro_rules! raw_pointer_to_ref {
    ($raw_p:expr) => {
        unsafe { &*$raw_p }
    };
}

#[derive(Debug, Clone, Copy)]
enum MachineState {
    LongCompat32,
    Long64,
}

// ref: xed-examples-utils.c

pub(crate) fn initialize() {
    llb::tables_init()
}

// for xed_decoded_inst_t
pub(crate) fn decode(
    bytes: &[u8],
    mode: MachineState,
) -> Result<llb::xed_decoded_inst_t, llb::xed_error_enum_t> {
    let xed_mode = match mode {
        MachineState::LongCompat32 => llb::xed_state_t {
            mmode: llb::xed_machine_mode_enum_t::XED_MACHINE_MODE_LONG_COMPAT_32,
            stack_addr_width: llb::xed_address_width_enum_t::XED_ADDRESS_WIDTH_32b,
        },

        MachineState::Long64 => llb::xed_state_t {
            mmode: llb::xed_machine_mode_enum_t::XED_MACHINE_MODE_LONG_64,
            stack_addr_width: llb::xed_address_width_enum_t::XED_ADDRESS_WIDTH_64b,
        },
    };

    let mut decoded_inst: llb::xed_decoded_inst_t = unsafe { mem::uninitialized() };
    let decoded_inst_ptr = &mut decoded_inst;

    // unsafe {
    //     llb::xed_decoded_inst_zero_set_mode(
    //         // &mut decoded_inst as *mut xed_decoded_inst_t,
    //         ref_to_mut_raw_pointer!(decoded_inst_ptr),
    //         &xed_mode as *const llb::xed_state_t,
    //     )
    // };
    llb::decoded_inst_zero_set_mode(&mut decoded_inst, &xed_mode);

    // let decoding_error = unsafe {
    //     llb::xed_decode(
    //         // &mut decoded_inst as *mut xed_decoded_inst_t,
    //         ref_to_mut_raw_pointer!(decoded_inst_ptr),
    //         bytes.as_ptr(),
    //         bytes.len() as u32,
    //     )
    // };
    let decoding_error = llb::decode(&mut decoded_inst, bytes);

    match decoding_error {
        llb::xed_error_enum_t::XED_ERROR_NONE => Ok(decoded_inst),
        err @ _ => Err(err),
    }
}

pub(crate) fn const_inst(inst: &llb::xed_decoded_inst_t) -> &llb::xed_inst_t {
    raw_pointer_to_ref!(inst._inst)
}

pub(crate) fn valid(inst: &llb::xed_decoded_inst_t) -> bool {
    // let inst = inst as *const xed_decoded_inst_t;
    let inst: *const llb::xed_decoded_inst_t = ref_to_raw_pointer!(inst);
    unsafe { (*inst)._inst as usize != 0 }
    // insider != 0
}

pub(crate) fn len(inst: &llb::xed_decoded_inst_t) -> u8 {
    let inst: *const llb::xed_decoded_inst_t = ref_to_raw_pointer!(inst);
    unsafe { (*inst)._decoded_length as u8 }
}

pub(crate) fn scalable(inst: &llb::xed_decoded_inst_t) -> bool {
    let inst = llb::decoded_inst_inst(inst).unwrap();
    llb::inst_get_attribute(inst, llb::xed_attribute_enum_t::XED_ATTRIBUTE_SCALABLE)
}

pub(crate) fn dump(inst: &llb::xed_decoded_inst_t) -> String {
    let mut buffer = [0i8; 1024 * 4];
    let raw_buffer = buffer.as_mut_ptr();
    unsafe {
        llb::xed_decoded_inst_dump(inst, raw_buffer, buffer.len() as i32);
        CStr::from_ptr(raw_buffer).to_str().unwrap().to_owned()
    }
}

pub(crate) fn dump_operand(op: &llb::xed_operand_t) -> String {
    let mut buffer = [0i8; 1024];
    let raw_buffer = buffer.as_mut_ptr();
    unsafe {
        llb::xed_operand_print(ref_to_raw_pointer!(op), raw_buffer, buffer.len() as i32);
        CStr::from_ptr(raw_buffer).to_str().unwrap().to_owned()
    }
}

pub(crate) fn disasm(
    inst: &llb::xed_decoded_inst_t,
    syntax: llb::xed_syntax_enum_t,
    base: u64,
) -> String {
    let mut buffer = [0i8; 256];
    let raw_buffer = buffer.as_mut_ptr();
    unsafe {
        let context = mem::transmute(0u64);
        let callback = mem::transmute(0u64);
        llb::xed_format_context(
            syntax,
            ref_to_raw_pointer!(inst),
            raw_buffer,
            buffer.len() as i32,
            base,
            context,
            callback,
        );
        CStr::from_ptr(raw_buffer).to_str().unwrap().to_owned()
    }
}

// pub(crate) fn conditonally_write_registers(inst: &llb::xed_decoded_inst_t) -> bool {
//     // let inst = inst as *const xed_decoded_inst_t;
//     let inst = ref_to_raw_pointer!(inst);
//     unsafe { llb::xed_decoded_inst_conditionally_writes_registers(inst) != 0 }
// }

pub(crate) fn uses_rflags(inst: &llb::xed_decoded_inst_t) -> bool {
    // let inst = inst as *const xed_decoded_inst_t;
    unsafe { llb::xed_decoded_inst_uses_rflags(ref_to_raw_pointer!(inst)) != 0 }
}

pub(crate) fn operands<'a>(inst: &'a llb::xed_decoded_inst_t) -> Option<Vec<&'a llb::xed_operand_t>> {
    llb::decoded_inst_inst(inst).map(|inst| {
        let operand_count = llb::inst_noperands(inst);

        let mut operands = Vec::with_capacity(operand_count as usize);
        for i in 0..operand_count {
            // let p_operand_i = unsafe { llb::xed_inst_operand(inst, i as u32) };
            let p_operand_i = llb::inst_operand(inst, i as u32).unwrap();
            operands.push(raw_pointer_to_ref!(p_operand_i));
        }

        operands
    })
}

// for xed_operand_t
// pub(crate) fn is_conditional_write(oprd: &llb::xed_operand_t) -> bool {
//     // let oprd = oprd as *const xed_operand_t;
//     let oprd = ref_to_raw_pointer!(oprd);
//     let cw = unsafe { llb::xed_operand_conditional_write(oprd) };
//     cw != 0
// }

// pub(crate) fn is_conditional_read(oprd: &llb::xed_operand_t) -> bool {
//     let oprd = oprd as *const llb::xed_operand_t;
//     let cw = unsafe { llb::xed_operand_conditional_read(oprd) };
//     cw != 0
// }

pub(crate) fn instruction_table() -> &'static [llb::xed_inst_t] {
    let base = unsafe { llb::xed_inst_table_base() };
    unsafe { slice::from_raw_parts(base, llb::XED_MAX_INST_TABLE_NODES as usize) }
    // let mut inst_vec = Vec::with_capacity(XED_MAX_INST_TABLE_NODES as usize);
    // for i in 0..XED_MAX_INST_TABLE_NODES {
    //     let inst = unsafe { slice::from_raw_parts(base, i as usize) };
    //     inst_vec.push(raw_pointer_to_ref!(inst));
    // }
    // inst_vec
}

// xed-ex1.c
pub(crate) fn has_rep(inst: &llb::xed_inst_t) -> bool {
    let iform = llb::iform_str(llb::inst_iform_enum(inst));
    iform.starts_with("REP_") || iform.starts_with("REPE_")
    // let iclass = xed_iform_to_iclass(iform);
    // let iclass_wo_rep = unsafe { xed_rep_remove(iclass) };
    // iclass != iclass_wo_rep
}

pub(crate) fn has_repne(inst: &llb::xed_inst_t) -> bool {
    let iform = llb::iform_str(llb::inst_iform_enum(inst));
    iform.starts_with("REPNE_")
}

pub(crate) fn check_inst(inst: &llb::xed_inst_t) {
    let stdout = io::stdout();
    let mut tabbed_stdout = {
        let w = stdout.lock();
        let w = io::BufWriter::new(w);
        TabWriter::new(w)
    };

    writeln!(
        tabbed_stdout,
        "========================================\n\
         iclass:\t{}",
        llb::iclass_str(llb::inst_iclass(inst))
    );

    writeln!(
        tabbed_stdout,
        "iform:\t{}",
        llb::iform_str(llb::inst_iform_enum(inst))
    );

    writeln!(
        tabbed_stdout,
        "category:\t{}",
        llb::category_str(llb::inst_category(inst))
    );

    writeln!(
        tabbed_stdout,
        "extension:\t{}",
        llb::extension_str(llb::inst_extension(inst))
    );

    writeln!(
        tabbed_stdout,
        "isa set:\t{}",
        llb::isa_str(llb::inst_isa_set(inst))
    );

    let sc = llb::inst_get_attribute(inst, llb::xed_attribute_enum_t::XED_ATTRIBUTE_SCALABLE);
    writeln!(
        tabbed_stdout,
        "scalable:\t{}", sc
    );

    let operand_count = llb::inst_noperands(inst);
    for i in 0..operand_count {
        let operand_i = llb::inst_operand(inst, i as u32).unwrap();

        // let name = llb::xed_operand_name(operand_i);
        let name = match llb::operand_type(operand_i) {
            llb::xed_operand_type_enum_t::XED_OPERAND_TYPE_NT_LOOKUP_FN => {
                llb::nonterminal_str(llb::operand_nonterminal_name(operand_i))
            }

            llb::xed_operand_type_enum_t::XED_OPERAND_TYPE_REG => {
                llb::reg_str(llb::operand_reg(operand_i))
            }

            _ => "unknown",
        };
        writeln!(
            tabbed_stdout,
            "operand:\t{}\n\tname:\t{}\n\ttype:\t{}\n\tvisibility:\t{}\n\taction:\t{}",
            llb::operand_name_str(llb::operand_name(operand_i)),
            name,
            llb::operand_type_str(llb::operand_type(operand_i)),
            llb::operand_visibility_str(llb::operand_operand_visibility(operand_i)),
            llb::operand_action_str(llb::operand_rw(operand_i))
        );
    }

    tabbed_stdout.flush();
}

// xed-doc-top.txt
pub(crate) fn encode(inst: &llb::xed_inst_t, state: MachineState) {
    let state = match state {
        MachineState::LongCompat32 => llb::xed_state_t {
            mmode: llb::xed_machine_mode_enum_t::XED_MACHINE_MODE_LONG_COMPAT_32,
            stack_addr_width: llb::xed_address_width_enum_t::XED_ADDRESS_WIDTH_32b,
        },

        MachineState::Long64 => llb::xed_state_t {
            mmode: llb::xed_machine_mode_enum_t::XED_MACHINE_MODE_LONG_64,
            stack_addr_width: llb::xed_address_width_enum_t::XED_ADDRESS_WIDTH_64b,
        },
    };

    let mut encoder_request: llb::xed_encoder_request_t = unsafe { mem::uninitialized() };
    unsafe {
        // let encoder_request = &mut encoder_request;
        llb::xed_encoder_request_zero_set_mode(
            ref_to_mut_raw_pointer!(&mut encoder_request),
            ref_to_raw_pointer!(&state),
        )
    };

    if has_rep(inst) {
        unsafe {
            llb::xed_encoder_request_set_rep(ref_to_mut_raw_pointer!(&mut encoder_request));
        }
    } else if has_repne(inst) {
        unsafe {
            llb::xed_encoder_request_set_repne(ref_to_mut_raw_pointer!(&mut encoder_request));
        }
    }

    unsafe {
        llb::xed_encoder_request_set_effective_operand_width(
            ref_to_mut_raw_pointer!(&mut encoder_request),
            64,
        );
        llb::xed_encoder_request_set_effective_address_size(
            ref_to_mut_raw_pointer!(&mut encoder_request),
            64,
        );
    }

    unsafe {
        llb::xed_encoder_request_set_iclass(
            ref_to_mut_raw_pointer!(&mut encoder_request),
            llb::inst_iclass(inst),
        );
    }

    let operand_count = llb::inst_noperands(inst);
    for i in 0..operand_count {
        let operand_i = unsafe { llb::xed_inst_operand(ref_to_raw_pointer!(inst), i as u32) };
        let operand_i: &llb::xed_operand_t = raw_pointer_to_ref!(operand_i);
    }
}

fn parse_assembly(hex_asm: &str) -> Vec<u8> {
    let mut hex_bytes = hex_asm
        .as_bytes()
        .iter()
        .filter_map(|b| match b {
            b'0'...b'9' => Some(b - b'0'),
            b'a'...b'f' => Some(b - b'a' + 10),
            b'A'...b'F' => Some(b - b'A' + 10),
            _ => None,
        })
        .fuse();

    let mut bytes = vec![];
    while let (Some(h), Some(l)) = (hex_bytes.next(), hex_bytes.next()) {
        bytes.push(h << 4 | l)
    }

    bytes
}

#[derive(Debug, StructOpt)]
struct Args {
    #[structopt(
        name = "table",
        short = "t",
        long = "table",
        conflicts_with = "asm",
        conflicts_with = "compat",
        help = "Print instruction table"
    )]
    table_printing: bool,

    #[structopt(
        name = "asm",
        required_unless = "table",
        help = "Instruction's bytes hex string"
    )]
    bytes: Option<String>,

    #[structopt(
        name = "compat",
        short = "c",
        help = "Compatibility mode (default: long mode)"
    )]
    compat: bool,

    #[structopt(
        name = "verbose",
        short = "v",
        help = "Show instruction dump"
    )]
    verbose: bool,
}

fn show_memory_operand<T: Write>(
    w: &mut T,
    inst: &llb::xed_decoded_inst_t,
    opr: &llb::xed_operand_t,
    opr_idx: u8,
) {
    let opr_idx = opr_idx as u32;
    let base_reg = unsafe { llb::xed_decoded_inst_get_base_reg(inst, opr_idx) };
    let seg_reg = {
        let seg = unsafe { llb::xed_decoded_inst_get_seg_reg(inst, opr_idx) };
        use self::llb::xed_reg_enum_t::*;
        match seg {
            XED_REG_INVALID => {
                let base_wide = unsafe { llb::xed_get_largest_enclosing_register(base_reg) };
                match base_wide {
                    XED_REG_RSP | XED_REG_RBP => XED_REG_SS,
                    _ => XED_REG_DS,
                }
            }

            _ => seg,
        }
    };

    let index_reg = unsafe { llb::xed_decoded_inst_get_index_reg(inst, opr_idx) };
    let disp = unsafe { llb::xed_decoded_inst_get_memory_displacement(inst, opr_idx) };
    let scale = unsafe { llb::xed_decoded_inst_get_scale(inst, opr_idx) };

    writeln!(
        w,
        "\tsegment:\t{}\n\
         \tbase:\t{}\n\
         \tindex:\t{}\n\
         \tdisp:\t{}\n\
         \tscale:\t{}",
        llb::reg_str(seg_reg),
        llb::reg_str(base_reg),
        llb::reg_str(index_reg),
        disp,
        scale
    );
}

fn main() {
    initialize();

    // let inst_table = instruction_table();
    // for inst in inst_table {
    //     println!("{}", xed::iform_str(xed::xed_inst_iform_enum(inst)));
    // }
    // return;

    let args = Args::from_args();
    if args.table_printing {
        let inst_table = instruction_table();
        for ref inst in inst_table {
            // println!("{}", llb::iform_str(llb::xed_inst_iform_enum(inst)));
            check_inst(inst)
        }
    } else {
        let bytes = parse_assembly(&args.bytes.unwrap());

        let mode = if args.compat {
            MachineState::LongCompat32
        } else {
            MachineState::Long64
        };

        let stdout = io::stdout();
        let mut tabbed_stdout = {
            let w = stdout.lock();
            let w = io::BufWriter::new(w);
            TabWriter::new(w)
        };

        match decode(&bytes, mode) {
            Ok(ref inst) => {
                let byte_count = unsafe { llb::decoded_inst_get_length(inst) };
                writeln!(tabbed_stdout, "byte count:\t{}", byte_count);

                writeln!(
                    tabbed_stdout,
                    "disassembly:\t{}",
                    disasm(&inst, llb::xed_syntax_enum_t::XED_SYNTAX_INTEL, 0u64)
                );

                let inst_base = llb::decoded_inst_inst(&inst).unwrap();

                writeln!(
                    tabbed_stdout,
                    "iclass:\t{}",
                    llb::iclass_str(llb::inst_iclass(inst_base))
                );

                let iform = llb::inst_iform_enum(inst_base);
                writeln!(tabbed_stdout, "iform:\t{}", llb::iform_str(iform));

                writeln!(
                    tabbed_stdout,
                    "category:\t{}",
                    llb::category_str(llb::inst_category(inst_base))
                );

                writeln!(
                    tabbed_stdout,
                    "isa extension:\t{}",
                    llb::extension_str(llb::inst_extension(inst_base))
                );

                writeln!(
                    tabbed_stdout,
                    "isa set:\t{}",
                    llb::isa_str(llb::inst_isa_set(inst_base))
                );

                writeln!(
                    tabbed_stdout,
                    "scalable:\t{}",
                    scalable(&inst)
                );

                writeln!(
                    tabbed_stdout,
                    "uses rflags:\t{}",
                    uses_rflags(&inst)
                );

                let attr_count = unsafe { llb::xed_attribute_max() };
                let mut attrs = Vec::with_capacity(attr_count as usize);
                for i in 0..attr_count {
                    let attr = unsafe { llb::xed_attribute(i) };
                    if llb::inst_get_attribute(inst_base, attr) {
                        attrs.push(llb::attribute_str(attr));
                    }
                }
                let attrs_string = attrs.join(" ");
                writeln!(tabbed_stdout, "attributes:\t{}", attrs_string);

                let legacy_prefixes_count = llb::decoded_inst_get_nprefixes(inst);
                    // unsafe { llb::xed_decoded_inst_get_nprefixes(ref_to_raw_pointer!(inst)) };
                writeln!(tabbed_stdout, "legacy prefixes:\t{}", legacy_prefixes_count);

                let remill_function_name = {
                    let has_lock_prefix = unsafe { llb::xed_operand_values_has_lock_prefix(inst) };
                    let iform = if has_lock_prefix != 0 {
                        *xed_nolock_iform_map.get(&iform).unwrap()
                    } else {
                        iform
                    };

                    let mut func_name = format!("{}", llb::iform_str(iform));

                    if scalable(inst) {
                        func_name = format!("{}_{}", func_name, unsafe {
                            llb::xed_decoded_inst_get_operand_width(inst)
                        });
                    }

                    func_name = match iform {
                        XED_IFORM_MOV_SEG_MEMw
                        | XED_IFORM_MOV_SEG_GPR16
                        | XED_IFORM_MOV_CR_CR_GPR32
                        | XED_IFORM_MOV_CR_CR_GPR64 => format!(
                            "{}_{}",
                            func_name,
                            llb::reg_str(unsafe {
                                llb::xed_decoded_inst_get_reg(
                                    inst,
                                    llb::xed_operand_enum_t::XED_OPERAND_REG0,
                                )
                            })
                        ),

                        _ => func_name,
                    };

                    func_name
                };

                writeln!(tabbed_stdout, "remill name:\t{}", remill_function_name);

                // operands
                let operand_count = llb::inst_noperands(inst_base);
                for i in 0..operand_count {
                    let operand_i = llb::inst_operand(inst_base, i as u32).unwrap();

                    let opr_name = llb::operand_name(operand_i);
                    let opr_type = llb::operand_type(operand_i);
                    let opr_vis = llb::operand_operand_visibility(operand_i);
                    let opr_act = llb::operand_rw(operand_i);

                    let value = match opr_type {
                        llb::xed_operand_type_enum_t::XED_OPERAND_TYPE_NT_LOOKUP_FN => {
                            llb::nonterminal_str(llb::operand_nonterminal_name(operand_i))
                        }

                        llb::xed_operand_type_enum_t::XED_OPERAND_TYPE_REG => {
                            llb::reg_str(llb::operand_reg(operand_i))
                        }

                        _ => "unknown",
                    };
                    writeln!(
                        tabbed_stdout,
                        "-----------------------------------------------------\n\
                         operand:\t{}\n\
                         \tvalue:\t{}\n\
                         \ttype:\t{}\n\
                         \tvisibility:\t{}\n\
                         \taction:\t{}",
                        llb::operand_name_str(opr_name),
                        value,
                        llb::operand_type_str(opr_type),
                        llb::operand_visibility_str(opr_vis),
                        llb::operand_action_str(opr_act),
                    );

                    use self::llb::xed_operand_enum_t::*;
                    match opr_name {
                        XED_OPERAND_MEM0 => {
                            show_memory_operand(&mut tabbed_stdout, inst, operand_i, 0);
                        }

                        XED_OPERAND_MEM1 => {
                            show_memory_operand(&mut tabbed_stdout, inst, operand_i, 1);
                        }

                        _ => {}
                    }
                }

                if args.verbose {
                    writeln!(tabbed_stdout, "\n{}", dump(&inst));
                }

                tabbed_stdout.flush().unwrap();
            }

            Err(err) => {
                println!("{}", llb::error_str(err));
            }
        }
    }
}

// tests:
// 48 8B 8C 19 C0 0F 00 00 mov rcx, [rcx+rbx+0xfc0]
// 48 8D 54 24 20          lea rdx, [rsp+0x20]
