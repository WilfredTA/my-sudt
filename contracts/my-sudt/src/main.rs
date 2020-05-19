#![no_std]
#![no_main]
#![feature(lang_items)]
#![feature(alloc_error_handler)]
#![feature(panic_info_message)]

use alloc::vec::Vec;
use ckb_std::{
    ckb_constants::{CellField, Source, SysError},
    default_alloc, entry, syscalls,
};
use ckb_types::{packed::Script, prelude::*};

entry!(main);
default_alloc!();

const BUF_LEN: usize = 1024;
const UDT_LEN: usize = 16;

// Error codes
#[repr(i8)]
enum Error {
    IndexOutOfBound = 1,
    ItemMissing,
    LengthNotEnough,
    Encoding, // data encoding error
    Amount,   // amount error
}

impl From<SysError> for Error {
    fn from(err: SysError) -> Self {
        use SysError::*;
        match err {
            IndexOutOfBound => Self::IndexOutOfBound,
            ItemMissing => Self::ItemMissing,
            LengthNotEnough(_) => Self::LengthNotEnough,
            Unknown(err_code) => panic!("unexpected sys error {}", err_code),
        }
    }
}

fn check_owner_mode(args: &[u8]) -> Result<bool, Error> {
    // With owner lock script extracted, we will look through each input in the
    // current transaction to see if any unlocked cell uses owner lock.
    let mut i = 0;
    let mut buf = [0u8; 32];
    loop {
        // check input's lock_hash with script args
        let len = match syscalls::load_cell_by_field(
            &mut buf,
            0,
            i,
            Source::Input,
            CellField::LockHash,
        ) {
            Ok(len) => len,
            Err(SysError::IndexOutOfBound) => return Ok(false),
            Err(err) => return Err(err.into()),
        };

        // invalid length of loaded data
        if len != buf.len() {
            return Err(Error::Encoding);
        }

        if args[..] == buf[..] {
            return Ok(true);
        }
        i += 1;
    }
}

fn collect_inputs_amount() -> Result<u128, Error> {
    // let's loop through all input cells containing current UDTs,
    // and gather the sum of all input tokens.
    let mut inputs_amount: u128 = 0;
    let mut i = 0;

    // u128 is 16 bytes
    let mut buf = [0u8; UDT_LEN];
    loop {
        // check input's lock_hash with script args
        let len = match syscalls::load_cell_data(&mut buf, 0, i, Source::GroupInput) {
            Ok(len) => len,
            Err(SysError::IndexOutOfBound) => break,
            Err(err) => return Err(err.into()),
        };

        if len != UDT_LEN {
            return Err(Error::Encoding);
        }
        inputs_amount += u128::from_le_bytes(buf);
        i += 1;
    }
    Ok(inputs_amount)
}

fn collect_outputs_amount() -> Result<u128, Error> {
    // With the sum of all input UDT tokens gathered, let's now iterate through
    // output cells to grab the sum of all output UDT tokens.
    let mut outputs_amount: u128 = 0;
    let mut i = 0;

    // u128 is 16 bytes
    let mut buf = [0u8; UDT_LEN];
    loop {
        // check input's lock_hash with script args
        let len = match syscalls::load_cell_data(&mut buf, 0, i, Source::GroupOutput) {
            Ok(len) => len,
            Err(SysError::IndexOutOfBound) => break,
            Err(err) => return Err(err.into()),
        };

        if len != UDT_LEN {
            return Err(Error::Encoding);
        }
        outputs_amount += u128::from_le_bytes(buf);
        i += 1;
    }
    Ok(outputs_amount)
}

fn check() -> Result<(), Error> {
    // load current script
    // check verification branch is owner mode or normal mode
    let script = {
        let mut buf = [0u8; BUF_LEN];
        let len = syscalls::load_script(&mut buf, 0)?;
        Script::new_unchecked(buf[..len].to_vec().into())
    };

    // unpack the Script#args field
    let args: Vec<u8> = script.args().unpack();

    // return success if owner mode is true
    if check_owner_mode(&args)? {
        return Ok(());
    }

    let inputs_amount = collect_inputs_amount()?;
    let outputs_amount = collect_outputs_amount()?;

    if inputs_amount < outputs_amount {
        return Err(Error::Amount);
    }

    Ok(())
}

#[no_mangle]
fn main() -> i8 {
    match check() {
        Ok(_) => 0,
        Err(err) => err as i8,
    }
}
