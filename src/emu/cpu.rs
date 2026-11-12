use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};

use crate::error::{exact_bytes, msg, Result};
use crate::flags;
use crate::gp::{self, Cpu};
use crate::ir::MemIo;

use super::{Api, Machine, SENTINEL};

impl Machine {
    pub fn run(&mut self) -> Result<()> {
        self.drive(|_| false)?;
        Ok(())
    }

    /// Run until `stop` is true. A later call continues without replaying TLS.
    pub fn drive(&mut self, mut stop: impl FnMut(&Self) -> bool) -> Result<bool> {
        if self.steps == 0 && self.exit_code.is_none() {
            super::startup::validate(self);
            if self.exit_code.is_none() {
                self.enter_tls()?;
            }
        }
        while self.exit_code.is_none() {
            if stop(self) {
                return Ok(true);
            }
            if self.steps >= self.policy.max_steps {
                return Err(msg(format!("emulator step limit at {:#x}", self.rip)));
            }
            self.steps += 1;
            self.step()?;
        }
        Ok(false)
    }

    pub fn step(&mut self) -> Result<()> {
        self.note_watch();
        if self.rip == SENTINEL {
            self.exit_code = Some(self.regs[0] as u32);
            return Ok(());
        }
        if super::instrument::trip(self)? {
            return Ok(());
        }
        let mut bytes = vec![0u8; 15];
        for len in (1..=15).rev() {
            if let Ok(got) = self.read(self.rip, len) {
                bytes[..len].copy_from_slice(&got);
                break;
            }
        }
        let mut decoder = Decoder::with_ip(64, &bytes, self.rip, DecoderOptions::NONE);
        let insn = decoder.decode();
        if insn.is_invalid() {
            return Err(msg(format!("invalid instruction at {:#x}", self.rip)));
        }
        self.exec(&insn)
    }

    fn exec(&mut self, insn: &Instruction) -> Result<()> {
        let next = insn.next_ip();
        if self.exec_integer(insn, next)? {
            return self.note_trap(insn);
        }
        if self.exec_x87(insn, next)? {
            return Ok(());
        }
        if self.exec_sse(insn, next)? {
            return Ok(());
        }
        match insn.mnemonic() {
            Mnemonic::Nop | Mnemonic::Endbr64 | Mnemonic::Endbr32 => self.rip = next,
            Mnemonic::Jmp => self.jmp(insn)?,
            Mnemonic::Call => self.call(insn, next)?,
            Mnemonic::Ret => self.ret()?,
            Mnemonic::Int => self.software_int(insn, next)?,
            Mnemonic::Syscall => self.syscall(next)?,
            other => {
                let Some(cond) = jcc_code(other) else {
                    return Err(msg(format!(
                        "emulator does not implement {other:?} at {:#x}",
                        self.rip
                    )));
                };
                self.jcc(insn, next, cond);
            }
        }
        Ok(())
    }

    fn enter_tls(&mut self) -> Result<()> {
        if self.tls.is_empty() {
            return Ok(());
        }
        let entry = self.rip;
        let base = image_base(self)?;
        for callback in self.tls.clone() {
            self.trace.push(callback);
            self.call_tls(callback, base)?;
            if self.fail_closed() {
                return Ok(());
            }
        }
        self.rip = entry;
        self.regs[0] = 0;
        Ok(())
    }

    fn call_tls(&mut self, callback: u64, base: u64) -> Result<()> {
        let saved = self.regs;
        self.regs[1] = base;
        self.regs[2] = 1;
        self.regs[8] = 0;
        let rsp = saved[4].wrapping_sub(8);
        self.regs[4] = rsp;
        self.write(rsp, &super::TLS_RETURN.to_le_bytes())?;
        self.rip = callback;
        self.finish_tls()?;
        let eax = self.regs[0];
        self.regs = saved;
        self.regs[0] = eax;
        Ok(())
    }

    fn finish_tls(&mut self) -> Result<()> {
        while self.exit_code.is_none() && self.rip != super::TLS_RETURN {
            if self.steps >= self.policy.max_steps {
                return Err(msg(format!("emulator step limit at {:#x}", self.rip)));
            }
            self.steps += 1;
            self.step()?;
        }
        Ok(())
    }

    fn fail_closed(&mut self) -> bool {
        if self.exit_code.is_some() {
            return true;
        }
        if self.regs[0] == 0xDEB6 {
            self.exit_code = Some(0xDEB6);
            return true;
        }
        false
    }

    fn note_trap(&mut self, insn: &Instruction) -> Result<()> {
        if insn.mnemonic() != Mnemonic::Pushfq || !self.policy.trap_flag {
            return Ok(());
        }
        let rsp = self.regs[4];
        let mut bits = u64::from_le_bytes(exact_bytes(&self.read(rsp, 8)?)?);
        bits |= 0x100;
        self.write(rsp, &bits.to_le_bytes())
    }

    fn note_watch(&mut self) {
        let rip = self.rip;
        let Some(index) = self.policy.watch.iter().position(|addr| *addr == rip) else {
            return;
        };
        self.trace.push(rip);
        self.policy.watch.remove(index);
    }

    fn exec_integer(&mut self, insn: &Instruction, next: u64) -> Result<bool> {
        let mut cpu = Cpu {
            regs: self.regs,
            flags: self.flags,
            af: self.af,
            df: self.df,
            gs: self.gs,
        };
        let touch = {
            let mut mem = EmuMem { machine: self };
            gp::apply(&mut cpu, &mut mem, insn)?
        };
        if touch.is_none() {
            return Ok(false);
        }
        self.regs = cpu.regs;
        self.flags = cpu.flags;
        self.af = cpu.af;
        self.df = cpu.df;
        self.rip = next;
        Ok(true)
    }

    fn exec_x87(&mut self, insn: &Instruction, next: u64) -> Result<bool> {
        if !crate::x87::is_x87(insn.mnemonic()) {
            return Ok(false);
        }
        let raw = self.read(insn.ip(), insn.len())?;
        let mut x87 = self.x87;
        let mut cpu = Cpu {
            regs: self.regs,
            flags: self.flags,
            af: self.af,
            df: self.df,
            gs: self.gs,
        };
        let ran = {
            let mut mem = EmuMem { machine: self };
            crate::x87::apply(&mut x87, &mut cpu, &mut mem, insn, &raw)
        };
        ran?;
        self.x87 = x87;
        self.regs = cpu.regs;
        self.flags = cpu.flags;
        self.af = cpu.af;
        self.df = cpu.df;
        self.rip = next;
        Ok(true)
    }

    fn exec_sse(&mut self, insn: &Instruction, next: u64) -> Result<bool> {
        if !crate::sse::accepts(insn) {
            return Ok(false);
        }
        let raw = self.read(insn.ip(), insn.len())?;
        let mut sse = self.sse;
        let mut x87 = self.x87;
        let mut cpu = Cpu {
            regs: self.regs,
            flags: self.flags,
            af: self.af,
            df: self.df,
            gs: self.gs,
        };
        let ran = {
            let mut mem = EmuMem { machine: self };
            crate::sse::apply(&mut sse, &mut x87, &mut cpu, &mut mem, insn, &raw)
        };
        ran?;
        self.sse = sse;
        self.x87 = x87;
        self.regs = cpu.regs;
        self.flags = cpu.flags;
        self.af = cpu.af;
        self.df = cpu.df;
        self.rip = next;
        Ok(true)
    }

    fn jcc(&mut self, insn: &Instruction, next: u64, cond: u8) {
        let target = insn.near_branch_target();
        if flags::cond_taken(cond, self.flags) {
            self.note_branch(target);
            self.rip = target;
        } else {
            self.rip = next;
        }
    }

    fn jmp(&mut self, insn: &Instruction) -> Result<()> {
        let target = if insn.op0_kind() == OpKind::Register {
            read_reg(self, insn.op_register(0))
        } else if insn.op0_kind() == OpKind::Memory {
            u64::from_le_bytes(exact_bytes(&self.read(mem_addr(self, insn)?, 8)?)?)
        } else {
            insn.near_branch_target()
        };
        self.note_branch(target);
        self.rip = target;
        Ok(())
    }

    fn call(&mut self, insn: &Instruction, next: u64) -> Result<()> {
        let target = match insn.op0_kind() {
            OpKind::Register => read_reg(self, insn.op_register(0)),
            OpKind::Memory => {
                u64::from_le_bytes(exact_bytes(&self.read(mem_addr(self, insn)?, 8)?)?)
            }
            _ => insn.near_branch_target(),
        };
        self.note_branch(target);
        if let Some(api) = self.hooks.get(&target).copied() {
            self.api(api)?;
            self.rip = next;
            return Ok(());
        }
        if !self.policy.interpret_cipher && chacha_helper(self, target) {
            apply_chacha(self)?;
            self.rip = next;
            return Ok(());
        }
        self.regs[4] = self.regs[4].wrapping_sub(8);
        self.write(self.regs[4], &next.to_le_bytes())?;
        self.rip = target;
        Ok(())
    }

    fn ret(&mut self) -> Result<()> {
        let bytes = self.read(self.regs[4], 8)?;
        self.regs[4] = self.regs[4].wrapping_add(8);
        self.rip = u64::from_le_bytes(exact_bytes(&bytes)?);
        self.note_branch(self.rip);
        if self.rip == SENTINEL {
            self.exit_code = Some(self.regs[0] as u32);
        }
        Ok(())
    }

    fn syscall(&mut self, next: u64) -> Result<()> {
        if self.pe_tls.is_some() {
            return Err(msg("raw syscall in the Windows-native emulator profile"));
        }
        let number = self.regs[0];
        let rdi = self.regs[7];
        let rsi = self.regs[6];
        let rdx = self.regs[2];
        let result = match number {
            1 => self.emu_write(rdi, rsi, rdx)?,
            9 => self.emu_mmap(rsi, rdx),
            158 => self.emu_arch_prctl(rdi, rsi)?,
            186 => 1u64,
            n if n == u64::from(crate::syscall::NR_STD_HANDLE) => std_handle_value(rdi),
            other => return Err(msg(format!("emulator syscall {other}"))),
        };
        self.regs[0] = result;
        self.regs[1] = 0;
        self.regs[11] = 0;
        self.rip = next;
        Ok(())
    }

    fn emu_write(&mut self, fd: u64, buf: u64, len: u64) -> Result<u64> {
        if fd != 1 {
            return Ok((-9i64) as u64);
        }
        let n = usize::try_from(len).map_err(|_| msg("write length does not fit"))?;
        let data = self.read(buf, n)?;
        self.stdout.extend(data);
        Ok(len)
    }

    fn emu_mmap(&mut self, length: u64, _prot: u64) -> u64 {
        if length == 0 || length > 16 * 1024 * 1024 {
            return (-12i64) as u64;
        }
        let len = (length as usize).next_multiple_of(0x1000);
        let Some(base) = fresh_base(&self.regions, len as u64) else {
            return (-12i64) as u64;
        };
        self.regions.push(super::Region {
            base,
            data: vec![0; len],
        });
        base
    }

    fn emu_arch_prctl(&mut self, code: u64, addr: u64) -> Result<u64> {
        match code {
            0x1001 => self.gs = addr,
            0x1004 => self.write(addr, &self.gs.to_le_bytes())?,
            _ => return Ok((-22i64) as u64),
        }
        Ok(0)
    }

    fn api(&mut self, api: Api) -> Result<()> {
        match api {
            Api::GetStdHandle => self.get_std_handle(),
            Api::WriteFile => self.write_file()?,
            Api::ExitProcess => self.exit_code = Some(self.regs[1] as u32),
            Api::IsDebuggerPresent => {
                self.regs[0] = u64::from(self.policy.is_debugger_present);
            }
            Api::CheckRemoteDebuggerPresent => self.remote_debugger()?,
            Api::GetTickCount64 => self.tick(),
            Api::GetThreadContext => self.thread_context()?,
            Api::CloseHandle => self.close_handle(),
            Api::SetHandleInformation => self.regs[0] = 1,
            Api::NtQueryInformationProcess => self.nt_query()?,
            Api::NtQueryInformationThread => self.nt_thread()?,
            Api::NtQuerySystemInformation => self.nt_system()?,
            Api::LoadLibraryA | Api::GetProcAddress => self.regs[0] = 0,
        }
        Ok(())
    }

    fn software_int(&mut self, insn: &Instruction, next: u64) -> Result<()> {
        if insn.immediate8() != 0x2d {
            return Err(msg(format!(
                "emulator does not implement int {:#x}",
                insn.immediate8()
            )));
        }
        // No debugger: the exception is delivered and eax reports clean.
        // A debugger swallows int 2d and RIP moves one byte past the next
        // instruction start. Both paths consume the byte the detector emits.
        self.regs[0] = u64::from(!self.policy.int2d);
        self.rip = next.wrapping_add(1);
        Ok(())
    }

    fn get_std_handle(&mut self) {
        self.regs[0] = std_handle_value(self.regs[1]);
    }

    fn write_file(&mut self) -> Result<()> {
        if self.regs[8] == u64::from(crate::trace::LINE_NUMBER) && self.regs[9] == 0 {
            let line = format!("vmkek-ok:{}\n", self.regs[2]);
            self.stdout.extend(line.into_bytes());
            self.regs[0] = 1;
            return Ok(());
        }
        let buf = self.regs[2];
        let len = self.regs[8] as usize;
        let data = self.read(buf, len)?;
        self.stdout.extend(data);
        if self.regs[9] != 0 {
            self.write(self.regs[9], &(len as u32).to_le_bytes())?;
        }
        self.regs[0] = 1;
        Ok(())
    }

    fn remote_debugger(&mut self) -> Result<()> {
        if self.regs[2] != 0 {
            self.write(self.regs[2], &self.policy.remote.to_le_bytes())?;
        }
        self.regs[0] = 1;
        Ok(())
    }

    fn tick(&mut self) {
        self.regs[0] = self.policy.tick;
        let jump = self.policy.tick_jump;
        self.policy.tick_jump = 0;
        let step = self.policy.tick_step.wrapping_add(jump);
        self.policy.tick = self.policy.tick.wrapping_add(step);
    }

    fn thread_context(&mut self) -> Result<()> {
        let ctx = self.regs[2];
        let drs = [
            self.policy.dr0,
            self.policy.dr1,
            self.policy.dr2,
            self.policy.dr3,
            self.policy.dr6,
            self.policy.dr7,
        ];
        for (index, value) in drs.into_iter().enumerate() {
            let at = ctx + 0x48 + index as u64 * 8;
            self.write(at, &value.to_le_bytes())?;
        }
        self.regs[0] = 1;
        Ok(())
    }

    fn close_handle(&mut self) {
        let trapped =
            self.regs[1] == crate::antidebug::PROTECTED_HANDLE && self.policy.protected_handle;
        self.regs[0] = u64::from(trapped);
    }

    fn nt_query(&mut self) -> Result<()> {
        let class = self.regs[2] as u32;
        let buf = self.regs[8];
        if buf == 0 {
            self.regs[0] = 0xC000_000D;
            return Ok(());
        }
        match class {
            0 => self.write(buf + 0x28, &0x1000u64.to_le_bytes())?,
            7 => self.write(buf, &self.policy.debug_port.to_le_bytes())?,
            0x1e => self.write(buf, &self.policy.debug_object.to_le_bytes())?,
            0x1f => self.write(buf, &self.policy.debug_flags.to_le_bytes())?,
            27 => return self.write_image_name(buf),
            _ => {
                self.regs[0] = 0xC000_0003;
                return Ok(());
            }
        }
        self.regs[0] = 0;
        Ok(())
    }

    fn nt_thread(&mut self) -> Result<()> {
        let class = self.regs[2] as u32;
        let buf = self.regs[8];
        if class != crate::antidebug::THREAD_HIDE || buf == 0 {
            self.regs[0] = 0xC000_0003;
            return Ok(());
        }
        self.write(buf, &[self.policy.thread_hidden])?;
        self.regs[0] = 0;
        Ok(())
    }

    fn nt_system(&mut self) -> Result<()> {
        let class = self.regs[1] as u32;
        let buf = self.regs[2];
        if buf == 0 {
            self.regs[0] = 0xC000_000D;
            return Ok(());
        }
        match class {
            crate::antidebug::SYSTEM_KERNEL_DEBUGGER => self.write_kernel_debugger(buf)?,
            crate::antidebug::SYSTEM_MODULE_INFORMATION => self.write_module_hash(buf)?,
            _ => {
                self.regs[0] = 0xC000_0003;
                return Ok(());
            }
        }
        self.regs[0] = 0;
        Ok(())
    }

    fn write_kernel_debugger(&mut self, buf: u64) -> Result<()> {
        let enabled = u8::from(self.policy.kernel_debugger);
        let absent = u8::from(!self.policy.kernel_debugger);
        self.write(buf, &[enabled, absent])
    }

    fn write_module_hash(&mut self, buf: u64) -> Result<()> {
        self.saw_weak_module = true;
        let hash = if self.policy.kernel_module.is_empty() {
            0
        } else {
            super::djb2(self.policy.kernel_module.as_bytes())
        };
        self.write(buf, &hash.to_le_bytes())
    }

    fn write_image_name(&mut self, buf: u64) -> Result<()> {
        let wide: Vec<u16> = self.policy.parent_image.encode_utf16().collect();
        let nbytes = wide.len() * 2;
        self.write(buf, &(nbytes as u16).to_le_bytes())?;
        self.write(buf + 2, &((nbytes + 2) as u16).to_le_bytes())?;
        let text = buf + 0x10;
        self.write(buf + 8, &text.to_le_bytes())?;
        let mut raw = Vec::with_capacity(nbytes + 2);
        for unit in wide {
            raw.extend(unit.to_le_bytes());
        }
        raw.extend(0u16.to_le_bytes());
        self.write(text, &raw)?;
        self.regs[0] = 0;
        Ok(())
    }
}

/// `push rdi; test rcx, rcx` plus the ChaCha expand constant.
fn chacha_helper(machine: &Machine, target: u64) -> bool {
    let Ok(bytes) = machine.read(target, 160) else {
        return false;
    };
    bytes.starts_with(&[0x57, 0x48, 0x85, 0xC9])
        && bytes
            .windows(5)
            .any(|word| word == [0xB8, 0x65, 0x78, 0x70, 0x61])
}

/// Native ChaCha20 for one helper call. `rdi` stays and `rsi` advances.
fn apply_chacha(machine: &mut Machine) -> Result<()> {
    let len = usize::try_from(machine.regs[1]).unwrap_or(usize::MAX);
    if len == 0 {
        return Ok(());
    }
    let src = machine.regs[6];
    let dst = machine.regs[7];
    let counter = machine.regs[10] as u32;
    let chain = machine.context_chain_ptr()?;
    let key = exact_bytes::<32>(&machine.read(chain, 32)?)?;
    let nonce_at = chain + crate::vm::CTX_INDEX as u64;
    let nonce = exact_bytes::<12>(&machine.read(nonce_at, 12)?)?;
    let mut data = machine.read(src, len)?;
    crate::vm::apply_keystream(&key, &nonce, counter, &mut data);
    machine.write(dst, &data)?;
    machine.regs[6] = src.wrapping_add(u64::try_from(len).unwrap_or(0));
    let blocks = u32::try_from(len.div_ceil(64)).unwrap_or(u32::MAX);
    machine.regs[10] = u64::from(counter.wrapping_add(blocks));
    Ok(())
}

fn image_base(machine: &Machine) -> Result<u64> {
    let bytes = machine.read(super::PEB + 0x10, 8)?;
    let raw = <[u8; 8]>::try_from(bytes.as_slice()).map_err(|_| msg("short image base"))?;
    Ok(u64::from_le_bytes(raw))
}

fn std_handle_value(id: u64) -> u64 {
    let id = id as u32;
    u64::from(id == 0xffff_fff5 || id == 0xffff_fff6)
}

fn read_reg(machine: &Machine, reg: Register) -> u64 {
    if matches!(
        reg,
        Register::AH | Register::CH | Register::DH | Register::BH
    ) {
        return (machine.regs[reg.full_register().number()] >> 8) & 0xff;
    }
    let full = machine.regs[reg.full_register().number()];
    let bits = reg.size() as u32 * 8;
    let mask = if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    full & mask
}

fn mem_addr(machine: &Machine, insn: &Instruction) -> Result<u64> {
    let operand = (0..insn.op_count())
        .find(|index| insn.op_kind(*index) == OpKind::Memory)
        .unwrap_or(0);
    insn.virtual_address(operand, 0, |reg, _, _| {
        if reg == Register::GS {
            Some(machine.gs)
        } else if reg.is_segment_register() {
            Some(0)
        } else if reg.is_gpr() {
            Some(machine.regs[reg.full_register().number()])
        } else {
            Some(0)
        }
    })
    .ok_or_else(|| msg("could not compute a memory address"))
}

fn jcc_code(mnemonic: Mnemonic) -> Option<u8> {
    Some(match mnemonic {
        Mnemonic::Jo => 0,
        Mnemonic::Jno => 1,
        Mnemonic::Jb => 2,
        Mnemonic::Jae => 3,
        Mnemonic::Je => 4,
        Mnemonic::Jne => 5,
        Mnemonic::Jbe => 6,
        Mnemonic::Ja => 7,
        Mnemonic::Js => 8,
        Mnemonic::Jns => 9,
        Mnemonic::Jp => 10,
        Mnemonic::Jnp => 11,
        Mnemonic::Jl => 12,
        Mnemonic::Jge => 13,
        Mnemonic::Jle => 14,
        Mnemonic::Jg => 15,
        _ => return None,
    })
}

struct EmuMem<'a> {
    machine: &'a mut Machine,
}

fn fresh_base(regions: &[super::Region], len: u64) -> Option<u64> {
    let mut at = 0x2100_0000u64;
    while at < 0x3000_0000 {
        let clash = regions.iter().any(|region| {
            let end = region.base + region.data.len() as u64;
            at < end && region.base < at + len
        });
        if !clash {
            return Some(at);
        }
        at += 0x1000;
    }
    None
}

impl MemIo for EmuMem<'_> {
    fn read(&mut self, addr: u64, len: usize) -> Result<Vec<u8>> {
        Machine::read(self.machine, addr, len)
    }

    fn write(&mut self, addr: u64, data: &[u8]) -> Result<()> {
        Machine::write(self.machine, addr, data)
    }
}
