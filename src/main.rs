use std::{
    env,
    fs::File,
    io::{Read, Write},
    mem::size_of,
    num::ParseIntError,
    os::unix::prelude::MetadataExt,
    process::Stdio,
    str::FromStr,
};

use crate::mini_rv32ima::MiniRV32IMAState;

pub mod mini_rv32ima;

pub static RAM_IMAGE_OFFSET: u32 = 0x80000000;

#[allow(non_upper_case_globals)]
static default64mbdtb: [u8; 1536] = [
    0xd0, 0x0d, 0xfe, 0xed, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x05, 0x00,
    0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0xe3, 0x00, 0x00, 0x04, 0xc8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x1b, 0x72, 0x69, 0x73, 0x63,
    0x76, 0x2d, 0x6d, 0x69, 0x6e, 0x69, 0x6d, 0x61, 0x6c, 0x2d, 0x6e, 0x6f, 0x6d, 0x6d, 0x75, 0x00,
    0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x19, 0x00, 0x00, 0x00, 0x26, 0x72, 0x69, 0x73, 0x63,
    0x76, 0x2d, 0x6d, 0x69, 0x6e, 0x69, 0x6d, 0x61, 0x6c, 0x2d, 0x6e, 0x6f, 0x6d, 0x6d, 0x75, 0x2c,
    0x71, 0x65, 0x6d, 0x75, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x63, 0x68, 0x6f, 0x73,
    0x65, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x37, 0x00, 0x00, 0x00, 0x2c,
    0x65, 0x61, 0x72, 0x6c, 0x79, 0x63, 0x6f, 0x6e, 0x3d, 0x75, 0x61, 0x72, 0x74, 0x38, 0x32, 0x35,
    0x30, 0x2c, 0x6d, 0x6d, 0x69, 0x6f, 0x2c, 0x30, 0x78, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x2c, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x20, 0x63, 0x6f, 0x6e, 0x73, 0x6f, 0x6c,
    0x65, 0x3d, 0x68, 0x76, 0x63, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01,
    0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x40, 0x38, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x00,
    0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x35, 0x6d, 0x65, 0x6d, 0x6f,
    0x72, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x41,
    0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xff, 0xc0, 0x00,
    0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x63, 0x70, 0x75, 0x73, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x45, 0x00, 0x0f, 0x42, 0x40,
    0x00, 0x00, 0x00, 0x01, 0x63, 0x70, 0x75, 0x40, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
    0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x58, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03,
    0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x35, 0x63, 0x70, 0x75, 0x00, 0x00, 0x00, 0x00, 0x03,
    0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
    0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x60, 0x6f, 0x6b, 0x61, 0x79, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x1b, 0x72, 0x69, 0x73, 0x63,
    0x76, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x67,
    0x72, 0x76, 0x33, 0x32, 0x69, 0x6d, 0x61, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x0b,
    0x00, 0x00, 0x00, 0x71, 0x72, 0x69, 0x73, 0x63, 0x76, 0x2c, 0x6e, 0x6f, 0x6e, 0x65, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x72, 0x75, 0x70, 0x74, 0x2d, 0x63, 0x6f,
    0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
    0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x7a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8b, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x0f,
    0x00, 0x00, 0x00, 0x1b, 0x72, 0x69, 0x73, 0x63, 0x76, 0x2c, 0x63, 0x70, 0x75, 0x2d, 0x69, 0x6e,
    0x74, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x58,
    0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01,
    0x63, 0x70, 0x75, 0x2d, 0x6d, 0x61, 0x70, 0x00, 0x00, 0x00, 0x00, 0x01, 0x63, 0x6c, 0x75, 0x73,
    0x74, 0x65, 0x72, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x63, 0x6f, 0x72, 0x65,
    0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xa0,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x73, 0x6f, 0x63, 0x00, 0x00, 0x00, 0x00, 0x03,
    0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03,
    0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03,
    0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x1b, 0x73, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x2d, 0x62,
    0x75, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa4,
    0x00, 0x00, 0x00, 0x01, 0x75, 0x61, 0x72, 0x74, 0x40, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xab,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x41,
    0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x1b, 0x6e, 0x73, 0x31, 0x36,
    0x38, 0x35, 0x30, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x70, 0x6f, 0x77, 0x65,
    0x72, 0x6f, 0x66, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04,
    0x00, 0x00, 0x00, 0xbb, 0x00, 0x00, 0x55, 0x55, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04,
    0x00, 0x00, 0x00, 0xc1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04,
    0x00, 0x00, 0x00, 0xc8, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x10,
    0x00, 0x00, 0x00, 0x1b, 0x73, 0x79, 0x73, 0x63, 0x6f, 0x6e, 0x2d, 0x70, 0x6f, 0x77, 0x65, 0x72,
    0x6f, 0x66, 0x66, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x72, 0x65, 0x62, 0x6f,
    0x6f, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xbb,
    0x00, 0x00, 0x77, 0x77, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xc1,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xc8,
    0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x1b,
    0x73, 0x79, 0x73, 0x63, 0x6f, 0x6e, 0x2d, 0x72, 0x65, 0x62, 0x6f, 0x6f, 0x74, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x73, 0x79, 0x73, 0x63, 0x6f, 0x6e, 0x40, 0x31,
    0x31, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04,
    0x00, 0x00, 0x00, 0x58, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x10,
    0x00, 0x00, 0x00, 0x41, 0x00, 0x00, 0x00, 0x00, 0x11, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x1b,
    0x73, 0x79, 0x73, 0x63, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01,
    0x63, 0x6c, 0x69, 0x6e, 0x74, 0x40, 0x31, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0xcf, 0x00, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x03,
    0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x41, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x1b,
    0x00, 0x00, 0x00, 0x1b, 0x73, 0x69, 0x66, 0x69, 0x76, 0x65, 0x2c, 0x63, 0x6c, 0x69, 0x6e, 0x74,
    0x30, 0x00, 0x72, 0x69, 0x73, 0x63, 0x76, 0x2c, 0x63, 0x6c, 0x69, 0x6e, 0x74, 0x30, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x09,
    0x23, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x2d, 0x63, 0x65, 0x6c, 0x6c, 0x73, 0x00, 0x23,
    0x73, 0x69, 0x7a, 0x65, 0x2d, 0x63, 0x65, 0x6c, 0x6c, 0x73, 0x00, 0x63, 0x6f, 0x6d, 0x70, 0x61,
    0x74, 0x69, 0x62, 0x6c, 0x65, 0x00, 0x6d, 0x6f, 0x64, 0x65, 0x6c, 0x00, 0x62, 0x6f, 0x6f, 0x74,
    0x61, 0x72, 0x67, 0x73, 0x00, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x5f, 0x74, 0x79, 0x70, 0x65,
    0x00, 0x72, 0x65, 0x67, 0x00, 0x74, 0x69, 0x6d, 0x65, 0x62, 0x61, 0x73, 0x65, 0x2d, 0x66, 0x72,
    0x65, 0x71, 0x75, 0x65, 0x6e, 0x63, 0x79, 0x00, 0x70, 0x68, 0x61, 0x6e, 0x64, 0x6c, 0x65, 0x00,
    0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x00, 0x72, 0x69, 0x73, 0x63, 0x76, 0x2c, 0x69, 0x73, 0x61,
    0x00, 0x6d, 0x6d, 0x75, 0x2d, 0x74, 0x79, 0x70, 0x65, 0x00, 0x23, 0x69, 0x6e, 0x74, 0x65, 0x72,
    0x72, 0x75, 0x70, 0x74, 0x2d, 0x63, 0x65, 0x6c, 0x6c, 0x73, 0x00, 0x69, 0x6e, 0x74, 0x65, 0x72,
    0x72, 0x75, 0x70, 0x74, 0x2d, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x00,
    0x63, 0x70, 0x75, 0x00, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x73, 0x00, 0x63, 0x6c, 0x6f, 0x63, 0x6b,
    0x2d, 0x66, 0x72, 0x65, 0x71, 0x75, 0x65, 0x6e, 0x63, 0x79, 0x00, 0x76, 0x61, 0x6c, 0x75, 0x65,
    0x00, 0x6f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x00, 0x72, 0x65, 0x67, 0x6d, 0x61, 0x70, 0x00, 0x69,
    0x6e, 0x74, 0x65, 0x72, 0x72, 0x75, 0x70, 0x74, 0x73, 0x2d, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x64,
    0x65, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

#[derive(Debug)]
struct RunOptions {
    image_file: String,
    dtb_file: String,
    kernel_command_line: String,
    fix_update: bool,
    do_sleep: bool,
    single_step: bool,
    fail_on_all_faults: bool,
    ram_amt: u32,
    time_divisor: u32,
    instct: Option<u32>,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            image_file: Default::default(),
            dtb_file: Default::default(),
            kernel_command_line: Default::default(),
            fix_update: false,
            do_sleep: true,
            single_step: false,
            fail_on_all_faults: false,
            ram_amt: 64 * 1024 * 1024,
            time_divisor: 1,
            instct: None,
        }
    }
}

fn main() {
    enum Help {
        Message(&'static str),
        Message2(String),
        GeneralHelp,
        Fine,
    }

    trait BaseParser {
        fn base_parse(self) -> Result<u32, ParseIntError>;
    }

    impl BaseParser for &str {
        fn base_parse(self) -> Result<u32, ParseIntError> {
            if let Some(num) = self.strip_prefix("0b") {
                u32::from_str_radix(num, 2)
            } else if let Some(num) = self.strip_prefix("0x") {
                u32::from_str_radix(num, 16)
            } else {
                u32::from_str(&self[2..])
            }
        }
    }

    let mut args = env::args();
    args.next();
    let mut options = RunOptions::default();

    macro_rules! expect_with_help {
        ($expected:expr, $status:expr) => {
            match $expected {
                Some(some) => some,
                None => break $status,
            }
        };
    }

    let status = loop {
        let arg = match args.next() {
            Some(some) => some,
            None => break Help::Fine,
        };
        match arg.as_str().trim() {
            "-m" => match expect_with_help!(args.next(), Help::Message("-m needs u32 argument"))
                .base_parse()
            {
                Ok(ok) => options.ram_amt = ok,
                Err(err) => break Help::Message2(format!("Invalid ram amount value: {err}")),
            },
            "-c" => match expect_with_help!(args.next(), Help::Message("-c needs u32 argument"))
                .base_parse()
            {
                Ok(ok) => options.instct = Some(ok),
                Err(err) => break Help::Message2(format!("Invalid instct value: {err}")),
            },
            "-k" => {
                options.kernel_command_line =
                    expect_with_help!(args.next(), Help::Message("-k needs string argument"))
            }
            "-f" => {
                options.image_file =
                    expect_with_help!(args.next(), Help::Message("-f needs string argument"))
            }
            "-b" => {
                options.dtb_file =
                    expect_with_help!(args.next(), Help::Message("-b needs string argument"))
            }
            "-l" => options.fix_update = true,
            "-p" => options.do_sleep = false,
            "-s" => options.single_step = true,
            "-d" => options.fail_on_all_faults = true,
            "-t" => match expect_with_help!(args.next(), Help::Message("-t needs u32 argument"))
                .base_parse()
            {
                Ok(ok) => options.time_divisor = ok,
                Err(err) => break Help::Message2(format!("Invalid time divisor value: {err}")),
            },
            arg => {
                println!("{}", arg);
                break Help::GeneralHelp;
            }
        }
    };

    if !matches!(status, Help::Fine) || options.image_file.is_empty() {
        match status {
            Help::Message(val) => println!("{}", val),
            Help::Message2(val) => println!("{}", val),
            _ => {
                println!("./mini-rv32imaf [parameters]\n\t-m [ram amount]\n\t-f [running image]\n\t-k [kernel command line]\n\t-b [dtb file, or 'disable']\n\t-c instruction count\n\t-s single step with full processor state\n\t-t time divion base\n\t-l lock time base to instruction count\n\t-p disable sleep when wfi\n\t-d fail out immediately on all faults\n");
            }
        }
        return;
    }

    // panic!("{:#?}", options);

    let mut ram: Vec<u8> = vec![0; options.ram_amt as usize];

    let mut file = File::open(options.image_file).expect("Failed to open image file");
    let size = file.metadata().map(|m| m.size()).unwrap_or(u64::MAX);
    if size > ram.len() as u64 {
        println!(
            "Not enough ram to fit image: ram:{}b image:{}b",
            ram.len(),
            size
        );
        return;
    }
    let read = file.read(&mut ram).expect("Failed to read file");
    if read as u64 != size {
        println!("Image wasnt entierly read?");
        return;
    }
    drop(file);

    let dtb_ptr;
    if !options.dtb_file.is_empty() {
        todo!()
    } else {
        dtb_ptr = ram.len() - default64mbdtb.len() - size_of::<MiniRV32IMAState>();
        ram[dtb_ptr..dtb_ptr + default64mbdtb.len()].copy_from_slice(&default64mbdtb);
        if !options.kernel_command_line.is_empty() {
            let start: usize = dtb_ptr + 0xc0;
            let end = start + 54.min(options.kernel_command_line.len());

            ram[start..end].copy_from_slice(options.kernel_command_line.as_bytes());
            ram[end..=start + 54].fill(0);
        }
    }

    //capture keyboard input
    capture_keyboard_input();

    let mut core = MiniRV32IMAState {
        pc: RAM_IMAGE_OFFSET,
        extrafalgs: 3,
        ..Default::default()
    };
    core.regs[10] = 0x00;
    core.regs[11] = if dtb_ptr != 0 {
        dtb_ptr as u32 + RAM_IMAGE_OFFSET
    } else {
        0
    };

    if options.dtb_file.is_empty() {
        let dtb = &mut ram[dtb_ptr..dtb_ptr + default64mbdtb.len()];
        let dtb =
            unsafe { std::slice::from_raw_parts_mut(dtb.as_ptr() as *mut u32, dtb.len() >> 2) };
        if dtb[0x13c / 4] == 0x00c0ff03 {
            let validram = dtb_ptr;
            dtb[0x13c / 4] = ((validram >> 24)
                | (((validram >> 16) & 0xff) << 8)
                | (((validram >> 8) & 0xff) << 16)
                | ((validram & 0xff) << 24)) as u32;
        }
    }

    let start = std::time::Instant::now();
    let mut last_time_us = 0u128;
    let steps = if options.single_step { 1 } else { 1024 };
    loop {
        let elapsed;
        if options.fix_update {
            elapsed = (core.cycle as u128) / (options.time_divisor as u128) - last_time_us;
            last_time_us += elapsed;
        } else {
            elapsed = (start.elapsed().as_micros()) / options.time_divisor as u128 - last_time_us;
            last_time_us += elapsed;
        }

        // std::io::stdin().bytes().peekable().p..next().unwrap().unwrap();
        // if let Ok(true) = crossterm::event::poll(std::time::Duration::ZERO) {
        //     if let Ok(crossterm::event::Event::Key(key)) = crossterm::event::read() {
        //         if key.code == KeyCode::Char('c') && key.modifiers == KeyModifiers::CONTROL{
        //             core.dump_state(&ram);
        //             println!("EXIT");
        //             break;
        //         }
        //     }
        // }

        if !matches!(core.pc, 0x800000b8 | 0x800000b4 | 0x800000b0)
            && options.single_step
            && core.cycle > 0x0000000003c53e60
        {
            // core.dump_state(&ram);
        }

        match core.step(&mut ram, 0, elapsed as u64, steps) {
            0 => {}
            1 => {
                if options.do_sleep {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    core.cycle += steps as u64;
                }
            }
            3 => {}
            0x7777 => {
                println!("restart");
                break;
            }
            0x5555 => {
                println!("Power off");
                break;
            }
            err => println!("Unknown error: {err}"),
        }
    }

    crossterm::terminal::disable_raw_mode().unwrap();
}

fn capture_keyboard_input() {
    crossterm::terminal::enable_raw_mode().unwrap();
}
