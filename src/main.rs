use std::{
    env, fs::File, io::Read, mem::size_of, num::ParseIntError, os::unix::prelude::MetadataExt,
    str::FromStr,
};

use crate::mini_rv32ima::MiniRV32IMAState;

pub mod mini_rv32ima;

pub static RAM_IMAGE_OFFSET: u32 = 0x80000000;

#[derive(Debug)]
struct RunOptions {
    image_file: String,
    dtb_file: String,
    kernel_command_line: Option<String>,
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

use vm_fdt::{Error, FdtWriter};
fn generate_default_dbt(ram: u64, bootargs: Option<&str>) -> Result<Vec<u8>, Error> {
    let mut fdt = FdtWriter::new()?;

    let root_node = fdt.begin_node("")?;
    fdt.property_u32("#address-cells", 0x1)?;
    fdt.property_u32("#size-cells", 0x1)?;
    fdt.property_string("compatible", "riscv-minimal-nommu")?;
    fdt.property_string("model", "riscv-minimal-nommu,qemu")?;

    let chosen_node = fdt.begin_node("chosen")?;
    fdt.property_string(
        "bootargs",
        bootargs.unwrap_or("earlycon=hvc0,mmio,0x10000000,1000000 console=hvc0 debug"),
    )?;
    // fdt.property_u32("linux,pci-probe-only", 1)?;
    fdt.end_node(chosen_node)?;

    let memory_node = fdt.begin_node("memory@80000000")?;
    fdt.property_string("device_type", "memory")?;
    fdt.property_array_u32("reg", &[0x80000000, ram as u32])?;
    fdt.end_node(memory_node)?;

    let cpu_node = fdt.begin_node("cpus")?;
    fdt.property_u32("#address-cells", 0x1)?;
    fdt.property_u32("#size-cells", 0x0)?;
    fdt.property_u32("timebase-frequency", 0x000F4240)?;

    {
        let cpu0_node = fdt.begin_node("cpu@0")?;
        fdt.property_u32("phandle", 0x1)?;
        fdt.property_string("device_type", "cpu")?;
        fdt.property_array_u32("reg", &[0x0])?;
        fdt.property_string("status", "okay")?;
        fdt.property_string("riscv,isa", "rv32ima")?;
        fdt.property("compatible", "bruhFamEpic\0riscv\0".as_bytes())?;
        fdt.property_string("mmu-type", "riscv,none")?;
        fdt.property_string("uarch", "bruhFamEpic")?;

        {
            let interrupt_node = fdt.begin_node("interrupt-controller")?;

            fdt.property_u32("#interrupt-cells", 0x1)?;
            fdt.property_null("interrupt-controller")?;
            fdt.property_string("compatible", "riscv,cpu-intc")?;
            fdt.property_u32("phandle", 20)?;

            fdt.end_node(interrupt_node)?;
        }

        fdt.end_node(cpu0_node)?;


        let cpu1_node = fdt.begin_node("cpu@1")?;
        fdt.property_u32("phandle", 0x2)?;
        fdt.property_string("device_type", "cpu")?;
        fdt.property_array_u32("reg", &[0x1])?;
        fdt.property_string("status", "okay")?;
        
        fdt.property("compatible", "bruhFamEpic\0riscv\0".as_bytes())?;

        fdt.end_node(cpu1_node)?;

        {
            let cpu_map_node = fdt.begin_node("cpu-map")?;
            {
                let cludter0_node = fdt.begin_node("cluster0")?;
                {
                    let core0_node = fdt.begin_node("core0")?;
                    fdt.property_u32("cpu", 0x1)?;

                    fdt.end_node(core0_node)?;

                    let core1_node = fdt.begin_node("core1")?;
                    fdt.property_u32("cpu", 0x2)?;

                    fdt.end_node(core1_node)?;
                }
                fdt.end_node(cludter0_node)?;
            }
            fdt.end_node(cpu_map_node)?;
        }
    }
    fdt.end_node(cpu_node)?;

    let soc_node = fdt.begin_node("soc")?;

    fdt.property_u32("#address-cells", 0x1)?;
    fdt.property_u32("#size-cells", 0x1)?;
    fdt.property_string("compatible", "simple-bus")?;
    fdt.property_null("ranges")?;

    {
        let uart_node = fdt.begin_node("uart@10000000")?;

        fdt.property_u32("clock-frequency", 0x01000000)?;
        fdt.property_array_u32("reg", &[0x10000000, 0x00000100])?;
        fdt.property_string("compatible", "ns16850")?;

        fdt.end_node(uart_node)?;

        let poweroff_node = fdt.begin_node("poweroff")?;

        fdt.property_u32("value", 0x5555)?;
        fdt.property_u32("offset", 0x0)?;
        fdt.property_u32("regmap", 0x4)?;
        fdt.property_string("compatible", "syscon-poweroff")?;

        fdt.end_node(poweroff_node)?;

        let reboot_node = fdt.begin_node("reboot")?;

        fdt.property_u32("value", 0x7777)?;
        fdt.property_u32("offset", 0x0)?;
        fdt.property_u32("regmap", 0x4)?;
        fdt.property_string("compatible", "syscon-reboot")?;

        fdt.end_node(reboot_node)?;

        let syscon_node = fdt.begin_node("syscon@11100000")?;

        fdt.property_u32("phandle", 0x4)?;
        fdt.property_array_u32("reg", &[0x11100000, 0x00001000])?;
        fdt.property_string("compatible", "syscon")?;

        fdt.end_node(syscon_node)?;

        let clint_node = fdt.begin_node("clint@11000000")?;

        fdt.property_array_u32("interrupts-extended", &[20, 0x3, 20, 0x7])?;
        fdt.property_array_u32("reg", &[0x11000000, 0x00010000])?;
        fdt.property("compatible", "sifive,clint0\0riscv,clint0\0".as_bytes())?;

        fdt.end_node(clint_node)?;
    }

    fdt.end_node(soc_node)?;

    fdt.end_node(root_node)?;

    fdt.finish()
}

fn main() {
    enum Help {
        Message(&'static str),
        Message2(String),
        General,
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
                options.kernel_command_line = expect_with_help!(
                    args.next().map(Some),
                    Help::Message("-k needs string argument")
                )
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
                break Help::General;
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
    if options.dtb_file.is_empty() {
        let dtb = generate_default_dbt(
            ram.len() as u64 - size_of::<MiniRV32IMAState>() as u64 - 0x1000,
            options.kernel_command_line.as_deref(),
        )
        .unwrap();
        assert!(dtb.len() < 0x1000);

        let dtb = &dtb;

        dtb_ptr = ram.len() - ((dtb.len() + 7) & !0b111) - size_of::<MiniRV32IMAState>();
        ram[dtb_ptr..dtb_ptr + dtb.len()].copy_from_slice(dtb);

        println!("{dtb_ptr:08X?}");

        // if !options.kernel_command_line.is_empty() {
        //     let start: usize = dtb_ptr + 0xc0;
        //     let end = start + 54.min(options.kernel_command_line.len());

        //     ram[start..end].copy_from_slice(options.kernel_command_line.as_bytes());
        //     ram[end..=start + 54].fill(0);
        // }

        // let dtb = &mut ram[dtb_ptr..dtb_ptr + default64mbdtb.len()];
        // let dtb =
        //     unsafe { std::slice::from_raw_parts_mut(dtb.as_ptr() as *mut u32, dtb.len() >> 2) };
        // if dtb[0x13c / 4] == 0x00c0ff03 {
        //     let validram = dtb_ptr;
        //     dtb[0x13c / 4] = (validram as u32).to_be();
        // }
    } else {
        todo!()
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
