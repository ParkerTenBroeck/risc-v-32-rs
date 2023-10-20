use std::{
    collections::VecDeque,
    io::{stdin, stdout, Read, Write},
    sync::{Arc, Mutex, OnceLock},
};

use crossterm::terminal::disable_raw_mode;

use crate::RAM_IMAGE_OFFSET;

#[derive(Default, Debug)]
pub struct MiniRV32IMAState {
    pub regs: [u32; 32],
    pub pc: u32,
    pub mstatus: u32,
    pub cycle: u64,
    pub timer: u64,
    pub timermatch: u64,
    pub mscratch: u32,
    pub mtvec: u32,
    pub mie: u32,
    pub mip: u32,
    pub mepc: u32,
    pub mtval: u32,
    pub mcause: u32,

    pub extrafalgs: u32,
}

impl MiniRV32IMAState {
    pub fn step(&mut self, ram: &mut [u8], proc_vaddress: u32, elapsed_us: u64, steps: u32) -> u32 {
        self.timer += elapsed_us;
        if self.timer > self.timermatch && self.timermatch != 0 {
            // print!("timer hit");
            self.extrafalgs &= !4;
            self.mip |= 1 << 7;
        } else {
            self.mip &= !(1 << 7);
        }
        if (self.extrafalgs & 4) != 0 {
            return 1;
        }

        macro_rules! load4 {
            ($expr:expr) => {
                unsafe {
                    std::slice::from_raw_parts_mut(ram.as_mut_ptr() as *mut u32, ram.len() / 4)
                        .get_unchecked_mut($expr >> 2)
                }
            };
        }
        macro_rules! load2 {
            ($expr:expr) => {
                unsafe {
                    std::slice::from_raw_parts_mut(ram.as_mut_ptr() as *mut u16, ram.len() / 4)
                        .get_unchecked_mut($expr >> 1)
                }
            };
        }
        macro_rules! load1 {
            ($expr:expr) => {
                unsafe { ram.get_unchecked_mut($expr) }
            };
        }

        let mut trap: u32 = 0;
        let mut rval: u32 = 0;
        let mut pc: u32 = self.pc;
        let mut cycle = self.cycle;

        if ((self.mip & (1 << 7)) != 0)
            && ((self.mie & (1 << 7)) != 0)
            && ((self.mstatus & 0x8) != 0)
        {
            trap = 0x80000007;
            pc -= 4;
        } else {
            for _icount in 0..steps {
                let ir: u32;
                rval = 0;
                cycle += 1;
                let ofs_pc: u32 = pc.wrapping_sub(RAM_IMAGE_OFFSET);

                if ofs_pc as usize >= ram.len() {
                    trap = 1 + 1;
                    break;
                } else if ofs_pc & 3 != 0 {
                    trap = 1 + 0;
                    break;
                } else {
                    ir = *load4!(ofs_pc as usize);
                    let mut rdid: u32 = (ir >> 7) & 0x1f;

                    match ir & 0x7F {
                        // LUI
                        0x37 => rval = ir & 0xfffff000,
                        //AUIPC
                        0x17 => rval = pc.wrapping_add(ir & 0xfffff000),
                        //JAL
                        0x6F => {
                            let mut reladdy = (((ir & 0x80000000) >> 11)
                                | ((ir & 0x7fe00000) >> 20)
                                | ((ir & 0x00100000) >> 9)
                                | (ir & 0x000ff000))
                                as i32;
                            if reladdy & 0x00100000 != 0 {
                                reladdy |= 0xffe00000u32 as i32;
                            } // Sign extension.
                            rval = pc.wrapping_add(4);
                            pc = pc.wrapping_add_signed(reladdy - 4);
                        }
                        //jalr
                        0x67 => {
                            let imm = ir >> 20;
                            let imm_se: i32 =
                                (imm | (if imm & 0x800 != 0 { 0xfffff000 } else { 0 })) as i32;
                            rval = pc.wrapping_add(4);
                            pc = (((self.regs[(ir as usize >> 15) & 0x1f])
                                .wrapping_add_signed(imm_se))
                                & !1)
                                .wrapping_sub(4)
                        }
                        //branch
                        0x63 => {
                            let mut imm4: u32 = ((ir & 0xf00) >> 7)
                                | ((ir & 0x7e000000) >> 20)
                                | ((ir & 0x80) << 4)
                                | ((ir >> 31) << 12);
                            if imm4 & 0x1000 != 0 {
                                imm4 |= 0xffffe000;
                            }
                            let rs1: i32 = self.regs[(ir as usize >> 15) & 0x1f] as i32;
                            let rs2: i32 = self.regs[(ir as usize >> 20) & 0x1f] as i32;
                            imm4 = pc.wrapping_add(imm4).wrapping_sub(4);
                            rdid = 0;
                            match (ir >> 12) & 0x7 {
                                0 => {
                                    if rs1 == rs2 {
                                        pc = imm4
                                    }
                                }
                                1 => {
                                    if rs1 != rs2 {
                                        pc = imm4
                                    }
                                }
                                4 => {
                                    if rs1 < rs2 {
                                        pc = imm4
                                    }
                                }
                                5 => {
                                    if rs1 >= rs2 {
                                        pc = imm4
                                    }
                                }
                                6 => {
                                    if (rs1 as u32) < (rs2 as u32) {
                                        pc = imm4
                                    }
                                }
                                7 => {
                                    if (rs1 as u32) >= (rs2 as u32) {
                                        pc = imm4
                                    }
                                }
                                _ => trap = 2 + 1,
                            }
                        }
                        //load
                        0x03 => {
                            let rs1: u32 = self.regs[(ir as usize >> 15) & 0x1f];
                            let imm: u32 = ir >> 20;
                            let imm_se: i32 =
                                (imm | if imm & 0x800 != 0 { 0xfffff000 } else { 0 }) as i32;
                            let mut rsval: u32 = rs1.wrapping_add_signed(imm_se);
                            rsval = rsval.wrapping_sub(RAM_IMAGE_OFFSET);
                            if rsval as usize >= ram.len() - 3 {
                                rsval = rsval.wrapping_add(RAM_IMAGE_OFFSET);
                                if (0x10000000..0x12000000).contains(&rsval) {
                                    if rsval == 0x1100bffc {
                                        rval = (self.timer >> 32) as u32;
                                    } else if rsval == 0x1100bff8 {
                                        rval = self.timer as u32;
                                    } else {
                                        rval = handle_mem_load_control(rsval);
                                    }
                                } else {
                                    trap = 5 + 1;
                                    rval = rsval;
                                }
                            } else {
                                match (ir >> 12) & 0x7 {
                                    0 => rval = *load1!(rsval as usize) as i8 as i32 as u32,
                                    1 => rval = *load2!(rsval as usize) as i16 as i32 as u32,
                                    2 => rval = *load4!(rsval as usize),
                                    4 => rval = *load1!(rsval as usize) as u32,
                                    5 => rval = *load2!(rsval as usize) as u32,
                                    _ => trap = 2 + 1,
                                }
                            }
                        }
                        //store
                        0x23 => {
                            let rs1: u32 = self.regs[(ir as usize >> 15) & 0x1f];
                            let rs2: u32 = self.regs[(ir as usize >> 20) & 0x1f];
                            let mut addy: u32 = ((ir >> 7) & 0x1f) | ((ir & 0xfe000000) >> 20);
                            if addy & 0x800 != 0 {
                                addy |= 0xfffff000;
                            }
                            addy = addy.wrapping_add(rs1.wrapping_sub(RAM_IMAGE_OFFSET));
                            rdid = 0;

                            if addy as usize >= ram.len() - 3 {
                                addy = addy.wrapping_add(RAM_IMAGE_OFFSET);
                                if (0x10000000..0x12000000).contains(&addy) {
                                    match addy {
                                        0x11004004 => {
                                            self.timermatch = ((rs2 as u64) << 32)
                                                | (self.timermatch & 0xFFFFFFFF)
                                        }
                                        0x11004000 => {
                                            self.timermatch = (rs2 as u64)
                                                | (self.timermatch & 0xFFFFFFFF00000000)
                                        }
                                        0x11100000 => {
                                            self.pc = pc.wrapping_add(4);
                                            return rs2;
                                        }
                                        0x10000000 => match char::from_u32(rs2) {
                                            Some(char) => print!("{char}"),
                                            None => print!("#[INVALID_CHAR 0x{:X}]", rs2),
                                        },
                                        _ => {
                                            // handle_mem_store_control
                                        }
                                    }
                                } else {
                                    trap = 7 + 1;
                                    break;
                                }
                            } else {
                                match (ir >> 12) & 0x7 {
                                    0 => *load1!(addy as usize) = rs2 as u8,
                                    1 => *load2!(addy as usize) = rs2 as u16,
                                    2 => *load4!(addy as usize) = rs2,
                                    _ => trap = 2 + 1,
                                }
                            }
                        }
                        //op immediate / op
                        0x13 | 0x33 => {
                            let imm: u32 = ir >> 20;
                            let imm = imm | if imm & 0x800 != 0 { 0xfffff000 } else { 0 };
                            let rs1 = self.regs[(ir as usize >> 15) & 0x1f];
                            let is_reg = ir & 0x20 != 0;
                            let rs2 = if is_reg {
                                self.regs[imm as usize & 0x1f]
                            } else {
                                imm
                            };
                            if is_reg && (ir & 0x02000000 != 0) {
                                match (ir >> 12) & 7 {
                                    0 => rval = rs1.wrapping_mul(rs2),
                                    1 => {
                                        rval = (((rs1 as i32 as i64)
                                            .wrapping_mul(rs2 as i32 as i64))
                                            >> 32)
                                            as u32
                                    }
                                    2 => {
                                        rval = ((rs1 as i32 as i64).wrapping_mul(rs2 as i64) >> 32)
                                            as u32
                                    }
                                    3 => {
                                        rval = ((rs1 as u64).wrapping_mul(rs2 as u64) >> 32) as u32
                                    }
                                    4 => {
                                        if rs2 == 0 {
                                            rval = -1i32 as u32;
                                        } else {
                                            rval = if (rs1 as i32) == i32::MIN && rs2 as i32 == -1 {
                                                rs1
                                            } else {
                                                ((rs1 as i32).wrapping_div(rs2 as i32)) as u32
                                            }
                                        }
                                    }
                                    5 => {
                                        if rs2 == 0 {
                                            rval = u32::MAX
                                        } else {
                                            rval = rs1.wrapping_div(rs2)
                                        }
                                    }
                                    6 => {
                                        if rs2 == 0 {
                                            rval = -1i32 as u32;
                                        } else {
                                            rval = if (rs1 as i32) == i32::MIN && rs2 as i32 == -1 {
                                                0
                                            } else {
                                                ((rs1 as i32).wrapping_rem(rs2 as i32)) as u32
                                            }
                                        }
                                    }
                                    7 => {
                                        if rs2 == 0 {
                                            rval = rs1
                                        } else {
                                            rval = rs1.wrapping_rem(rs2)
                                        }
                                    }
                                    _ => trap = 2 + 1,
                                }
                            } else {
                                match (ir >> 12) & 7 {
                                    0 => {
                                        rval = if is_reg && (ir & 0x40000000 != 0) {
                                            rs1.wrapping_sub(rs2)
                                        } else {
                                            rs1.wrapping_add(rs2)
                                        }
                                    }
                                    1 => rval = rs1 << (rs2 & 0x1f),
                                    2 => rval = if (rs1 as i32) < (rs2 as i32) { 1 } else { 0 },
                                    3 => rval = if rs1 < rs2 { 1 } else { 0 },
                                    4 => rval = rs1 ^ rs2,
                                    5 => {
                                        rval = if ir & 0x40000000 != 0 {
                                            (rs1 as i32 >> (rs2 & 0x1f)) as u32
                                        } else {
                                            rs1 >> (rs2 & 0x1f)
                                        }
                                    }
                                    6 => rval = rs1 | rs2,
                                    7 => rval = rs1 & rs2,
                                    _ => trap = 2 + 1,
                                }
                            }
                        }
                        //fencetype = (ir >> 12) & 0b111; We ignore fences in this impl.
                        0x0f => rdid = 0,
                        //Zifencei + Zicsr
                        0x73 => {
                            let csrno = ir >> 20;
                            let microop = (ir >> 12) & 0x7;
                            if microop & 3 != 0 {
                                //zicsr function
                                let rslimm = (ir >> 15) & 0x1f;
                                let rs1 = self.regs[rslimm as usize];
                                let mut writeval = rs1;

                                match csrno {
                                    0x340 => rval = self.mscratch,
                                    0x305 => rval = self.mtvec,
                                    0x304 => rval = self.mie,
                                    0xC00 => rval = cycle as u32,
                                    0x344 => rval = self.mip,
                                    0x341 => rval = self.mepc,
                                    0x300 => rval = self.mstatus, //mstatus
                                    0x342 => rval = self.mcause,
                                    0x343 => rval = self.mtval,
                                    0xf11 => rval = 0xff0ff0ff, //mvendorid
                                    0x301 => rval = 0x40401101, //misa (XLEN=32, IMA+X)
                                    _ => rval = handle_other_cs_read(csrno),
                                }

                                match microop {
                                    1 => writeval = rs1,
                                    2 => writeval = rval | rs1,
                                    3 => writeval = rval & !rs1,
                                    5 => writeval = rslimm,
                                    6 => writeval = rval | rslimm,
                                    7 => writeval = rval & !rslimm,
                                    _ => trap = 2 + 1,
                                }

                                match csrno {
                                    0x340 => self.mscratch = writeval,
                                    0x305 => self.mtvec = writeval,
                                    0x304 => self.mie = writeval,
                                    0x344 => self.mip = writeval,
                                    0x341 => self.mepc = writeval,
                                    0x300 => self.mstatus = writeval, //mstatus
                                    0x342 => self.mcause = writeval,
                                    0x343 => self.mtval = writeval,
                                    _ => handle_other_cs_write(ram, csrno, writeval),
                                }
                            } else if microop == 0x0 {
                                // system function
                                rdid = 0;
                                if csrno == 0x105 {
                                    //wait for interrupts
                                    self.mstatus |= 8;
                                    self.extrafalgs |= 4;
                                    self.pc = pc.wrapping_add(4);
                                    return 1;
                                } else if csrno & 0xff == 0x02 {
                                    //mret
                                    let startmstatus = self.mstatus;
                                    let startextraflags = self.extrafalgs;
                                    self.mstatus = ((startmstatus & 0x80) >> 4)
                                        | ((startextraflags & 3) << 11)
                                        | 0x80;
                                    self.extrafalgs =
                                        (startextraflags & !3) | ((startmstatus >> 11) & 3);
                                    pc = self.mepc.wrapping_sub(4);
                                } else {
                                    match csrno {
                                        0 => {
                                            trap = if self.extrafalgs & 3 != 0 {
                                                11 + 1
                                            } else {
                                                8 + 1
                                            }
                                        }
                                        1 => trap = 3 + 1,
                                        _ => trap = 2 + 1,
                                    }
                                }
                            } else {
                                trap = 2 + 1
                            }
                        }
                        // rv32a
                        0x2f => {
                            let mut rs1: u32 = self.regs[(ir as usize >> 15) & 0x1f];
                            let mut rs2: u32 = self.regs[(ir as usize >> 20) & 0x1f];
                            let irmid: u32 = (ir >> 27) & 0x1f;

                            rs1 -= RAM_IMAGE_OFFSET;

                            if rs1 as usize >= ram.len() - 3 {
                                trap = 7 + 1; //store amo access fault
                                rval = rs1 + RAM_IMAGE_OFFSET;
                            } else {
                                rval = *load4!(rs1 as usize);

                                let mut dowrite = true;
                                match irmid {
                                    2 => {
                                        //LR.W (0b00010)
                                        dowrite = false;
                                        self.extrafalgs = self.extrafalgs & 0x07 | rs1 << 3;
                                    }
                                    3 => {
                                        //SC.W (0b00011) (Make sure we have a slot, and, it's valid)
                                        let dowrite = self.extrafalgs >> 3 != rs1 & 0x1fffffff;

                                        rval = if dowrite { 1 } else { 0 };
                                    }
                                    1 => {
                                        //AMOSWAP.W (0b00001)
                                    }
                                    //AMOADD.W (0b00000)
                                    0 => rs2 = rs2.wrapping_add(rval),
                                    //AMOXOR.W (0b00100)
                                    4 => rs2 ^= rval,
                                    //AMOADD.W (0b00000)
                                    12 => rs2 &= rval,
                                    //AMOOR.W (0b01000)
                                    8 => rs2 |= rval,
                                    //AMOMIN.W (0b10000)
                                    16 => {
                                        rs2 = if (rs2 as i32) < (rval as i32) {
                                            rs2
                                        } else {
                                            rval
                                        }
                                    }
                                    //AMOMAX.W (0b10100)
                                    20 => {
                                        rs2 = if (rs2 as i32) > (rval as i32) {
                                            rs2
                                        } else {
                                            rval
                                        }
                                    }
                                    //AMOMINU.W (0b11000)
                                    24 => rs2 = if rs2 < rval { rs2 } else { rval },
                                    //AMOMAXU.W (0b11100)
                                    28 => rs2 = if rs2 > rval { rs2 } else { rval },
                                    _ => {
                                        trap = 2 + 1;
                                        dowrite = false;
                                    }
                                }
                                if dowrite {
                                    *load4!(rs1 as usize) = rs2;
                                }
                            }
                        }
                        _ => trap = 2 + 1,
                    }

                    if trap != 0 {
                        break;
                    }

                    if rdid != 0 {
                        self.regs[rdid as usize] = rval;
                    }
                }

                // post_exec(pc, ir, trap);
                if trap > 0 {
                    if
                    /*fail on all faults */
                    false {
                        println!("fault");
                        return 3;
                    } else {
                        // trap = retval;
                    }
                }

                pc = pc.wrapping_add(4);
            }
        }

        if trap != 0 {
            if trap & 0x80000000 != 0 {
                self.mcause = trap;
                self.mtval = 0;
                pc += 4;
            } else {
                self.mcause = trap - 1;
                self.mtval = if trap > 5 && trap <= 8 { rval } else { pc };
            }
            self.mepc = pc;
            self.mstatus = ((self.mstatus & 0x08) << 4) | ((self.extrafalgs & 3) << 11);
            pc = self.mtvec.wrapping_sub(4);
            self.extrafalgs |= 3;
            trap = 0;
            pc = pc.wrapping_add(4);
        }

        self.cycle = cycle;
        self.pc = pc;
        0
    }

    pub fn dump_state(&self, ram: &[u8]) {
        macro_rules! load4 {
            ($expr:expr) => {
                unsafe {
                    std::slice::from_raw_parts(ram.as_ptr() as *const u32, ram.len() / 4)
                        .get_unchecked($expr >> 2)
                }
            };
        }
        let pc: u32 = self.pc;
        let pc_offset: u32 = pc - RAM_IMAGE_OFFSET;
        let mut ir: u32 = 0;

        print!("PC: {:08x} ", pc);
        if (pc_offset as usize) < ram.len() - 3 {
            ir = *load4!(pc_offset as usize);
            print!("[0x{:08x}] ", ir);
        } else {
            print!("[xxxxxxxxxx] ");
        }

        let regs = self.regs;
        print!( "Z:{:08x} ra:{:08x} sp:{:08x} gp:{:08x} tp:{:08x} t0:{:08x} t1:{:08x} t2:{:08x} s0:{:08x} s1:{:08x} a0:{:08x} a1:{:08x} a2:{:08x} a3:{:08x} a4:{:08x} a5:{:08x} ",
           regs[0], regs[1], regs[2], regs[3], regs[4], regs[5], regs[6], regs[7],
           regs[8], regs[9], regs[10], regs[11], regs[12], regs[13], regs[14], regs[15] );
        print!( "a6:{:08x} a7:{:08x} s2:{:08x} s3:{:08x} s4:{:08x} s5:{:08x} s6:{:08x} s7:{:08x} s8:{:08x} s9:{:08x} s10:{:08x} s11:{:08x} t3:{:08x} t4:{:08x} t5:{:08x} t6:{:08x}",
           regs[16], regs[17], regs[18], regs[19], regs[20], regs[21], regs[22], regs[23],
           regs[24], regs[25], regs[26], regs[27], regs[28], regs[29], regs[30], regs[31] );

        print!(" mcause:{:08x} mepc:{:08x} mie:{:08x} mip:{:08x} mscratch:{:08x} ststatus{:08x} mtval:{:08x} mtvec:{:08x} extraflags:{:08x} timer:{:016x} timermatch:{:016x} cycle:{:016x}",         
            self.mcause,
            self.mepc,
            self.mie,
            self.mip,
            self.mscratch,
            self.mstatus,
            self.mtval,
            self.mtvec,
            self.extrafalgs,
            self.timer,
            self.timermatch,
            self.cycle,
        );
        println!()
    }
}

fn handle_mem_load_control(addy: u32) -> u32 {
    if addy == 0x10000005 {
        0x60 | if is_kb_hit() { 1 } else { 0 }
    } else if addy == 0x10000000 && is_kb_hit() {
        read_kb_byte() as u32
    } else {
        0
    }
}

static DUMB_INPUT: OnceLock<Arc<Mutex<VecDeque<u8>>>> = std::sync::OnceLock::new();

fn get_bruh() -> Arc<Mutex<VecDeque<u8>>> {
    DUMB_INPUT
        .get_or_init(|| {
            let arc = Arc::new(Mutex::new(VecDeque::new()));
            let clone = arc.clone();
            std::thread::spawn(move || {
                while let Some(Ok(byte)) = stdin().bytes().next() {
                    if byte == 3 {
                        disable_raw_mode().unwrap();
                        std::process::exit(0);
                    }
                    arc.lock().unwrap().push_back(byte);
                }
            });
            clone
        })
        .clone()
}

fn read_kb_byte() -> u8 {
    let byte = get_bruh().lock().unwrap().pop_front().unwrap_or(0xFF);
    byte
}

fn is_kb_hit() -> bool {
    !get_bruh().lock().unwrap().is_empty()
}

fn handle_other_cs_write(ram: &mut [u8], csrno: u32, writeval: u32) {
    if csrno == 0x136 {
        print!("{}", writeval as i32)
    } else if csrno == 0x137 {
        print!("{:08x}", writeval)
    } else if csrno == 0x138 {
        let ptrstart = writeval - RAM_IMAGE_OFFSET;
        let mut ptrend = ptrstart;
        while ram[ptrend as usize] != 0 {
            ptrend += 1;
        }
        if let Ok(string) = std::str::from_utf8(&ram[ptrstart as usize..ptrend as usize]) {
            println!("{string}")
        } else {
            println!("Invalid string");
        }
    } else if csrno == 0x139 {
        if let Some(char) = char::from_u32(writeval) {
            print!("{}", char)
        } else {
            print!("[{{INVALID CHAR}}: 0x{:08X}]", writeval)
        }
    }
    stdout().flush().unwrap()
}

fn handle_other_cs_read(csrno: u32) -> u32 {
    if csrno == 0x140 {
        // return u32::MAX
        return if !is_kb_hit() {
            u32::MAX
        } else {
            read_kb_byte() as u32
        };
    }
    0
}
