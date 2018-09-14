#[allow(unused, dead_code)]
extern crate structopt;
extern crate xed_sys;

use std::{mem, slice};
use structopt::StructOpt;

use xed_sys::*; // low-level binding xed

#[derive(Debug)]
enum MachineMode {
    LongCompat32,
    Long64,
}

pub(crate) fn initialize() {
    unsafe { xed_tables_init() }
}

// for xed_decoded_inst_t
pub(crate) fn decode(
    bytes: &[u8],
    mode: MachineMode,
) -> Result<xed_decoded_inst_t, xed_error_enum_t> {
    let xed_mode = match mode {
        MachineMode::LongCompat32 => xed_state_t {
            mmode: xed_machine_mode_enum_t::XED_MACHINE_MODE_LONG_COMPAT_32,
            stack_addr_width: xed_address_width_enum_t::XED_ADDRESS_WIDTH_32b,
        },

        MachineMode::Long64 => xed_state_t {
            mmode: xed_machine_mode_enum_t::XED_MACHINE_MODE_LONG_64,
            stack_addr_width: xed_address_width_enum_t::XED_ADDRESS_WIDTH_64b,
        },
    };

    let mut decoded_inst: xed_decoded_inst_t = unsafe { mem::uninitialized() };

    unsafe {
        xed_decoded_inst_zero_set_mode(
            &mut decoded_inst as *mut xed_decoded_inst_t,
            &xed_mode as *const xed_state_t,
        )
    };

    let decoding_error = unsafe {
        xed_decode(
            &mut decoded_inst as *mut xed_decoded_inst_t,
            bytes.as_ptr(),
            bytes.len() as u32,
        )
    };

    match decoding_error {
        xed_error_enum_t::XED_ERROR_NONE => Ok(decoded_inst),

        err @ _ => Err(err),
    }
}

pub(crate) fn len(inst: &xed_decoded_inst_t) -> u8 {
    let inst = inst as *const xed_decoded_inst_t;
    unsafe { (*inst)._decoded_length as u8 }
}

pub(crate) fn iclass(inst: &xed_decoded_inst_t) -> xed_iclass_enum_t {
    let inst = inst as *const xed_decoded_inst_t;
    unsafe { xed_operand_values_get_iclass(inst) }
}

pub(crate) fn operands(inst: &xed_decoded_inst_t) -> Vec<xed_operand_t> {
    let inst = inst as *const xed_decoded_inst_t;
    let p_inst = unsafe { (*inst)._inst };
    let operand_count = unsafe { (*p_inst)._noperands } as usize;

    let mut operands = Vec::with_capacity(operand_count);
    for i in 0..operand_count {
        let p_operand_i = unsafe { xed_inst_operand(p_inst, i as u32) };
        let operand_i = unsafe { (*p_operand_i).clone() };
        operands.push(operand_i);
        // operand_i = unsafe { slice::from_raw_parts(data: *const T, len: usize) }
        // operands.push(value: T)
    }

    operands
}

// for xed_operand_t
pub(crate) fn is_conditional_write(oprd: &xed_operand_t) -> bool {
    let oprd = oprd as *const xed_operand_t;
    let cw = unsafe { xed_operand_conditional_write(oprd) };
    if cw == 0 {
        false
    } else {
        true
    }
}

pub(crate) fn is_conditional_read(oprd: &xed_operand_t) -> bool {
    let oprd = oprd as *const xed_operand_t;
    let cw = unsafe { xed_operand_conditional_read(oprd) };
    if cw == 0 {
        false
    } else {
        true
    }
}

#[derive(Debug, StructOpt)]
struct Args {
    #[structopt(name = "asm", help = "Instruction's bytes hex string")]
    bytes: String,

    #[structopt(
        name = "compat",
        help = "Compatibility mode (default: long mode)"
    )]
    compat: bool,
}

fn main() {
    fn parse_assembly(hex_asm: &str) -> Vec<u8> {
        let mut hex_bytes = hex_asm
            .as_bytes()
            .iter()
            .filter_map(|b| match b {
                b'0'...b'9' => Some(b - b'0'),
                b'a'...b'f' => Some(b - b'a' + 10),
                b'A'...b'F' => Some(b - b'A' + 10),
                _ => None,
            }).fuse();

        let mut bytes = vec![];
        while let (Some(h), Some(l)) = (hex_bytes.next(), hex_bytes.next()) {
            bytes.push(h << 4 | l)
        }

        bytes
    }

    let args = Args::from_args();
    let bytes = parse_assembly(&args.bytes);

    initialize();

    let mode = if args.compat {
        MachineMode::LongCompat32
    } else {
        MachineMode::Long64
    };

    if let Ok(inst) = decode(&bytes, mode) {
        let operands = operands(&inst);
        let mut is_conditional = false;

        for oprd in &operands {
            if is_conditional_read(oprd) || is_conditional_write(oprd) {
                is_conditional = true;
                break;
            }
        }

        if is_conditional {
            println!("Instruction is conditional");
        } else {
            println!("Instruction is not conditional");
        }
    } else {
        println!("Invalid bytes");
    }
}
