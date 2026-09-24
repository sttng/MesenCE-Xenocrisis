#include "pch.h"
#include "Rp2040.h"
#include <cmath>
#include <cstdio>
#include <algorithm>

// ---------------------------------------------------------------------------------------------
// Firmware-specific HLE hook addresses.
// These belong to the "Xeno Crisis SNES v1.00" RP2040 image (pico-sdk 1.5.1, built Mar 27 2024).
// LoadFlash() verifies the code at each address before enabling the hooks.
// ---------------------------------------------------------------------------------------------
namespace XcHook
{
	enum : int
	{
		SetSysClockPll = 1, //set_sys_clock_pll(): no clock tree to program
		StdioInitAll,       //stdio_init_all(): no USB CDC
		Puts,               //puts()   -> log
		Printf,             //printf() -> log
		Panic,              //panic()  -> fault
		LaunchCore1,        //multicore_launch_core1(entry)
		SleepUntil,         //sleep_until(absolute_time_t)
		BusInit,            //SNES bus init (PIO0 SM0/1/2 + 2 DMA channels)
		BusFlush,           //abort DMA + flush PIO FIFOs
		BusWaitTx,          //wait until the TX DMA channel is idle
		BusSend,            //queue a generated 65816 code/data buffer for the SNES
		BusRecv,            //read N bytes written by the SNES to $3000 (with timeout)
		BusPush,            //push raw bytes straight into the PIO TX FIFO
		FlashErase,         //flash_range_erase(offset, count)
		FlashProgram,       //flash_range_program(offset, data, count)
		FlashDoCmd,         //flash_do_cmd(tx, rx, count): raw SPI command (unique ID read at boot)
		BootRomLookup,      //synthetic bootrom rom_table_lookup()
		Core1Exit,          //core 1 entry function returned
		BrrEncode,          //core 1 audio: brute-force BRR encoder for one 16-sample block (RAM function, hot)
	};

	//Location of the .data/.time_critical image in flash and its RAM destination (used to verify RAM hooks)
	static constexpr uint32_t DataLoadAddr = 0x10CDD2D4;
	static constexpr uint32_t DataStart = 0x200000C0;
	static constexpr uint32_t DataEnd = 0x20004E94;

	struct HookDef { uint32_t Addr; int Id; uint16_t FirstOp; };
	// FirstOp = first Thumb halfword of the function (sanity check against a different build)
	static const HookDef Defs[] = {
		{ 0x10054288, SetSysClockPll, 0xb5f0 },
		{ 0x10056eb6, StdioInitAll, 0xb510 },
		{ 0x10056e3c, Puts, 0xb570 },
		{ 0x10056ea0, Printf, 0xb40f },
		{ 0x100555c0, Panic, 0xb40f },
		{ 0x10059060, LaunchCore1, 0x4905 },
		{ 0x10054ecc, SleepUntil, 0xb5f0 },
		{ 0x10066d94, BusInit, 0xb5f0 },
		{ 0x100670cc, BusFlush, 0x22a0 },
		{ 0x10067188, BusWaitTx, 0x22a0 },
		{ 0x100671a4, BusSend, 0xb570 },
		{ 0x100671f4, BusRecv, 0xb5f7 },
		{ 0x10067274, BusPush, 0x4b0a },
		{ 0x1006e690, FlashErase, 0xb401 },
		{ 0x1006e610, FlashProgram, 0xb401 },
		{ 0x1006e560, FlashDoCmd, 0xb401 },
		{ 0x20000a00, BrrEncode, 0x2300 },
	};
}

//Portable bit helpers (MSVC has no __builtin_*)
static inline uint32_t PopCount32(uint32_t v)
{
	v = v - ((v >> 1) & 0x55555555);
	v = (v & 0x33333333) + ((v >> 2) & 0x33333333);
	return (((v + (v >> 4)) & 0x0F0F0F0F) * 0x01010101) >> 24;
}

static inline uint32_t ByteSwap32(uint32_t v)
{
	return (v >> 24) | ((v >> 8) & 0xFF00) | ((v << 8) & 0xFF0000) | (v << 24);
}

static inline uint32_t CountLeadingZeros32(uint32_t v)
{
	uint32_t n = 0;
	if(!v) {
		return 32;
	}
	while(!(v & 0x80000000)) {
		v <<= 1;
		n++;
	}
	return n;
}

static inline uint32_t CountTrailingZeros32(uint32_t v)
{
	uint32_t n = 0;
	if(!v) {
		return 32;
	}
	while(!(v & 1)) {
		v >>= 1;
		n++;
	}
	return n;
}

static constexpr uint32_t BootRomLookupAddr = 0x0300;
static constexpr uint32_t BootRomFuncBase = 0x1000;  //trap addresses for bootrom functions
static constexpr uint32_t BootRomFloatBase = 0x1400; //trap addresses for soft-float table entries
static constexpr uint32_t BootRomDoubleBase = 0x1600; //trap addresses for soft-double table entries
static constexpr uint32_t Core1ExitAddr = 0x3FF0;

static const char* BootRomFuncCodes[] = {
	"P3", "R3", "L3", "T3", "MS", "S4", "MC", "C4", "IF", "EX", "RE", "RP", "FC", "CX", "UB", "DT", "DE", "WV"
};

Rp2040::Rp2040()
{
	Flash.assign(FlashSize, 0xFF);
	Sram.assign(SramSize, 0);
	BootRom.assign(BootRomSize, 0);
	UsbRam.assign(0x1000, 0);
	_hookBits.assign((FlashSize + SramSize) / 16, 0);
	BuildBootRom();
}

void Rp2040::Fault(const std::string& msg)
{
	if(!Faulted) {
		Faulted = true;
		FaultMessage = msg;
		if(Log) {
			char buf[128];
			snprintf(buf, sizeof(buf), " [core%d pc=%08X lr=%08X sp=%08X]", _cur, Cores[_cur].R[15], Cores[_cur].R[14], Cores[_cur].R[13]);
			Log("RP2040 fault: " + msg + buf);
		}
	}
}

void Rp2040::BuildBootRom()
{
	auto w16 = [&](uint32_t a, uint16_t v) { BootRom[a] = v & 0xFF; BootRom[a + 1] = v >> 8; };
	auto w32 = [&](uint32_t a, uint32_t v) { w16(a, v & 0xFFFF); w16(a + 2, v >> 16); };

	w32(0x00, 0x20042000);
	w32(0x04, 0x000000EB);
	BootRom[0x10] = 'M'; BootRom[0x11] = 'u'; BootRom[0x12] = 0x01;
	BootRom[0x13] = 3; //bootrom version (B2 silicon)
	w16(0x14, 0x0100); //function table
	w16(0x16, 0x0200); //data table
	w16(0x18, BootRomLookupAddr | 1);

	uint32_t p = 0x100;
	for(size_t i = 0; i < sizeof(BootRomFuncCodes) / sizeof(BootRomFuncCodes[0]); i++) {
		w16(p, (uint16_t)(BootRomFuncCodes[i][0] | (BootRomFuncCodes[i][1] << 8)));
		w16(p + 2, (uint16_t)((BootRomFuncBase + i * 4) | 1));
		p += 4;
	}
	w16(p, 0);

	//Data table: soft float/double function tables (entries are trap addresses)
	p = 0x200;
	w16(p, 'S' | ('F' << 8)); w16(p + 2, 0x0800); p += 4;
	w16(p, 'S' | ('D' << 8)); w16(p + 2, 0x0A00); p += 4;
	w16(p, 'C' | ('R' << 8)); w16(p + 2, 0x0C00); p += 4;
	w16(p, 0);
	for(int i = 0; i < 0x80 / 4; i++) {
		w32(0x0800 + i * 4, (BootRomFloatBase + i * 4) | 1);
		w32(0x0A00 + i * 4, (BootRomDoubleBase + i * 4) | 1);
	}
	const char* cr = "(C) 2020 Raspberry Pi Trading Ltd";
	memcpy(&BootRom[0x0C00], cr, strlen(cr) + 1);
}

bool Rp2040::LoadFlash(const uint8_t* data, size_t size, std::string& error)
{
	if(size > FlashSize || size < 0x1000) {
		error = "RP2040 flash image must be between 4KB and 16MB";
		return false;
	}
	std::fill(Flash.begin(), Flash.end(), 0xFF);
	memcpy(Flash.data(), data, size);

	std::fill(_hookBits.begin(), _hookBits.end(), 0);
	_hooks.clear();
	for(const XcHook::HookDef& h : XcHook::Defs) {
		uint32_t off;
		if(h.Addr >= XcHook::DataStart && h.Addr < XcHook::DataEnd) {
			off = XcHook::DataLoadAddr - 0x10000000 + (h.Addr - XcHook::DataStart);
		} else {
			off = h.Addr - 0x10000000;
		}
		uint16_t op = (uint16_t)(Flash[off] | (Flash[off + 1] << 8));
		if(h.FirstOp && op != h.FirstOp) {
			char buf[128];
			snprintf(buf, sizeof(buf), "unexpected firmware build (code at %08X is %04X, expected %04X)", h.Addr, op, h.FirstOp);
			error = buf;
			return false;
		}
		AddHook(h.Addr, h.Id);

		if(h.Id == XcHook::FlashErase || h.Id == XcHook::FlashProgram || h.Id == XcHook::FlashDoCmd) {
			//These are flash-side veneers ("push {r0}; ldr r0,=ram_func; mov ip,r0; pop {r0}; bx ip") to RAM functions.
			//Hook the RAM targets too in case RAM code calls them directly.
			uint32_t ramTarget = Flash[off + 12] | (Flash[off + 13] << 8) | (Flash[off + 14] << 16) | (Flash[off + 15] << 24);
			if((ramTarget & 0xFFF00000) == 0x20000000) {
				AddHook(ramTarget & ~1u, h.Id);
			}
		}
	}
	AddHook(BootRomLookupAddr, XcHook::BootRomLookup);
	AddHook(Core1ExitAddr, XcHook::Core1Exit);
	return true;
}

void Rp2040::AddHook(uint32_t addr, int id)
{
	_hooks[addr] = id;
	uint32_t idx;
	if((addr & 0xFF000000) == 0x10000000) {
		idx = (addr & 0xFFFFFF) / 2;
	} else if((addr & 0xFF000000) == 0x20000000 && (addr & 0xFFFFFF) < SramSize) {
		idx = (FlashSize + (addr & 0xFFFFFF)) / 2;
	} else {
		return; //bootrom addresses are always checked
	}
	_hookBits[idx >> 3] |= 1 << (idx & 7);
}

void Rp2040::PowerOn()
{
	std::fill(Sram.begin(), Sram.end(), 0);
	_periph.clear();
	_spinlocks = 0;
	_globalCycle = 0;
	TxFifo.clear();
	RxFifo.clear();
	Faulted = false;
	FaultMessage.clear();
	InstructionCount = 0;
	_timerLatchHigh = 0;
	_alarmArmed = 0;
	_sliceTarget = 0;

	for(int i = 0; i < 2; i++) {
		Cores[i] = Core();
	}

	//The firmware image starts with the 256-byte boot2 stage; the application vector table follows at +0x100.
	//Emulate what boot2 does: jump to the application with SP/PC from its vector table and VTOR pointing at it.
	Core& c = Cores[0];
	c.Vtor = 0x10000100;
	c.R[13] = Read32(0x10000100);
	c.R[15] = Read32(0x10000104) & ~1u;
	c.R[14] = 0xFFFFFFFF;
	c.Running = true;
	Cores[1].Running = false;
}

uint32_t Rp2040::CallForTest(uint32_t addr, const std::vector<uint32_t>& args, bool allowHle, uint64_t* cycles)
{
	static constexpr uint32_t TestReturnAddr = 0x3FE0;
	Core saved = Cores[0];
	Core& c = Cores[0];
	c.Running = true;
	c.InHle = false;
	uint32_t sp = (c.R[13] - 0x400) & ~7u;
	for(size_t i = 4; i < args.size(); i++) {
		Write32(sp + (uint32_t)(i - 4) * 4, args[i]);
	}
	for(size_t i = 0; i < 4 && i < args.size(); i++) {
		c.R[i] = args[i];
	}
	c.R[13] = sp;
	c.R[14] = TestReturnAddr | 1;
	c.R[15] = addr & ~1u;
	_testNoHle = !allowHle;
	_cur = 0;
	uint64_t start = c.Cycles;
	uint64_t guard = 0;
	while(c.R[15] != TestReturnAddr && !Faulted && guard++ < 100000000) {
		Step(c);
	}
	_testNoHle = false;
	uint32_t result = c.R[0];
	if(cycles) {
		*cycles = c.Cycles - start;
	}
	Cores[0] = saved;
	return result;
}

// ---------------------------------------------------------------------------------------------
// Save states
// ---------------------------------------------------------------------------------------------
namespace
{
	struct BlobWriter
	{
		std::vector<uint8_t>& Out;
		template<typename T> void Pod(const T& v) { const uint8_t* p = (const uint8_t*)&v; Out.insert(Out.end(), p, p + sizeof(T)); }
		void Bytes(const uint8_t* p, size_t n) { Pod((uint32_t)n); Out.insert(Out.end(), p, p + n); }
	};
	struct BlobReader
	{
		const std::vector<uint8_t>& In;
		size_t Pos = 0;
		bool Ok = true;
		template<typename T> void Pod(T& v) { if(Pos + sizeof(T) > In.size()) { Ok = false; return; } memcpy(&v, &In[Pos], sizeof(T)); Pos += sizeof(T); }
		void Bytes(uint8_t* p, size_t n) { uint32_t len = 0; Pod(len); if(len != n || Pos + n > In.size()) { Ok = false; return; } memcpy(p, &In[Pos], n); Pos += n; }
	};
	constexpr uint32_t StateVersion = 1;
}

void Rp2040::SaveState(std::vector<uint8_t>& out)
{
	out.clear();
	BlobWriter w { out };
	w.Pod(StateVersion);
	for(Core& c : Cores) {
		w.Pod(c);
	}
	w.Pod(_globalCycle);
	w.Pod(_spinlocks);
	w.Pod(_fifoToCore);
	w.Pod(_timerLatchHigh);
	w.Pod(InstructionCount);
	w.Bytes(Sram.data(), Sram.size());
	w.Bytes(UsbRam.data(), UsbRam.size());
	w.Bytes(&Flash[SaveOffset], SaveSize);
	w.Pod((uint32_t)_periph.size());
	for(auto& kv : _periph) {
		w.Pod(kv.first);
		w.Pod(kv.second);
	}
	std::vector<uint8_t> tx(TxFifo.begin(), TxFifo.end()), rx(RxFifo.begin(), RxFifo.end());
	w.Pod((uint32_t)tx.size());
	out.insert(out.end(), tx.begin(), tx.end());
	w.Pod((uint32_t)rx.size());
	out.insert(out.end(), rx.begin(), rx.end());
}

bool Rp2040::LoadState(const std::vector<uint8_t>& in)
{
	BlobReader r { in };
	uint32_t version = 0;
	r.Pod(version);
	if(version != StateVersion) {
		return false;
	}
	for(Core& c : Cores) {
		r.Pod(c);
	}
	r.Pod(_globalCycle);
	r.Pod(_spinlocks);
	r.Pod(_fifoToCore);
	r.Pod(_timerLatchHigh);
	r.Pod(InstructionCount);
	r.Bytes(Sram.data(), Sram.size());
	r.Bytes(UsbRam.data(), UsbRam.size());
	r.Bytes(&Flash[SaveOffset], SaveSize);
	uint32_t count = 0;
	r.Pod(count);
	_periph.clear();
	for(uint32_t i = 0; i < count && r.Ok; i++) {
		uint32_t k = 0, v = 0;
		r.Pod(k);
		r.Pod(v);
		_periph[k] = v;
	}
	auto readQueue = [&](std::deque<uint8_t>& q) {
		uint32_t n = 0;
		r.Pod(n);
		q.clear();
		for(uint32_t i = 0; i < n && r.Ok; i++) {
			uint8_t b = 0;
			r.Pod(b);
			q.push_back(b);
		}
	};
	readQueue(TxFifo);
	readQueue(RxFifo);
	_alarmArmed = Get(0x40054020);
	Faulted = false;
	return r.Ok;
}

// ---------------------------------------------------------------------------------------------
// SNES side
// ---------------------------------------------------------------------------------------------
uint8_t Rp2040::SnesRead()
{
	if(TxFifo.empty()) {
		//PIO program does "pull ifempty noblock": empty FIFO -> OSR = X = 0
		return 0x00;
	}
	uint8_t v = TxFifo.front();
	TxFifo.pop_front();
	return v;
}

void Rp2040::SnesWrite(uint8_t value)
{
	RxFifo.push_back(value);
}

// ---------------------------------------------------------------------------------------------
// Scheduling
// ---------------------------------------------------------------------------------------------
void Rp2040::RunUntil(uint64_t cycle)
{
	if(Faulted) {
		_globalCycle = cycle;
		return;
	}

	while(_globalCycle < cycle) {
		uint64_t sliceEnd = std::min(cycle, _globalCycle + SliceCycles);
		for(int i = 0; i < 2; i++) {
			if(Cores[i].Running) {
				RunCore(i, sliceEnd);
			} else {
				Cores[i].Cycles = sliceEnd;
			}
			if(Faulted) {
				_globalCycle = cycle;
				return;
			}
		}
		_globalCycle = sliceEnd;
		if(_alarmArmed) {
			UpdateTimerAlarms();
		}
	}
}

void Rp2040::RunCore(int id, uint64_t target)
{
	_cur = id;
	_sliceTarget = target;
	Core& c = Cores[id];
	const uint8_t* flash = Flash.data();
	const uint8_t* sram = Sram.data();
	const uint8_t* hookBits = _hookBits.data();

	while(c.Cycles < target && c.Running && !Faulted) {
		if(c.NvicPending) {
			CheckInterrupts(c);
		}

		//Fast path: code in XIP flash or SRAM (everything else, e.g. bootrom traps, goes through Step)
		uint32_t pc = c.R[15];
		const uint8_t* code;
		uint32_t hookIdx;
		uint32_t offset = pc & 0xFFFFFF;
		if((pc >> 24) == 0x10) {
			code = flash + offset;
			hookIdx = offset >> 1;
		} else if((pc >> 24) == 0x20 && offset < SramSize - 4) {
			code = sram + offset;
			hookIdx = (FlashSize + offset) >> 1;
		} else {
			Step(c);
			continue;
		}

		if((hookBits[hookIdx >> 3] >> (hookIdx & 7)) & 1) {
			if(!_testNoHle && HandleHle(c, pc)) {
				continue;
			}
		}

		uint16_t op = (uint16_t)(code[0] | (code[1] << 8));
		c.Cycles++;
		InstructionCount++;
		if((op >> 11) >= 0x1D) {
			c.R[15] = pc + 4;
			Exec32(c, op, (uint16_t)(code[2] | (code[3] << 8)));
		} else {
			c.R[15] = pc + 2;
			Exec16(c, op);
		}
	}
}

// ---------------------------------------------------------------------------------------------
// Memory
// ---------------------------------------------------------------------------------------------
uint8_t* Rp2040::GetMemPtr(uint32_t addr, uint32_t size, bool write)
{
	switch(addr >> 24) {
		case 0x00:
			if(!write && addr + size <= BootRomSize) {
				return &BootRom[addr];
			}
			break;

		case 0x10: case 0x11: case 0x12: case 0x13:
			if(!write) {
				return &Flash[addr & 0xFFFFFF];
			}
			break;

		case 0x20: case 0x21:
			if((addr & 0xFFFFFF) + size <= SramSize) {
				return &Sram[addr & 0xFFFFFF];
			}
			break;

		case 0x50:
			if((addr & 0xFFFFF000) == 0x50100000) {
				return &UsbRam[addr & 0xFFF];
			}
			break;
	}
	return nullptr;
}

uint32_t Rp2040::Read32(uint32_t addr)
{
	addr &= ~3u;
	if((addr >> 24) == 0x20 && (addr & 0xFFFFFF) < SramSize) {
		uint32_t v;
		memcpy(&v, &Sram[addr & 0xFFFFFF], 4);
		return v;
	}
	if(uint8_t* p = GetMemPtr(addr, 4, false)) {
		uint32_t v;
		memcpy(&v, p, 4);
		return v;
	}
	switch(addr >> 28) {
		case 0x4: case 0x5: return ReadPeriph(addr);
		case 0xD: return ReadSio(addr);
		case 0xE: return ReadPpb(addr);
	}
	if((addr >> 24) == 0x18 || (addr >> 24) == 0x14 || (addr >> 24) == 0x15) {
		return 0; //SSI / XIP control
	}
	char buf[64];
	snprintf(buf, sizeof(buf), "read32 from unmapped address %08X", addr);
	Fault(buf);
	return 0;
}

uint16_t Rp2040::Read16(uint32_t addr)
{
	addr &= ~1u;
	if(uint8_t* p = GetMemPtr(addr, 2, false)) {
		return (uint16_t)(p[0] | (p[1] << 8));
	}
	return (uint16_t)(Read32(addr) >> ((addr & 2) * 8));
}

uint8_t Rp2040::Read8(uint32_t addr)
{
	if(uint8_t* p = GetMemPtr(addr, 1, false)) {
		return *p;
	}
	return (uint8_t)(Read32(addr) >> ((addr & 3) * 8));
}

void Rp2040::Write32(uint32_t addr, uint32_t value)
{
	addr &= ~3u;
	if((addr >> 24) == 0x20 && (addr & 0xFFFFFF) < SramSize) {
		memcpy(&Sram[addr & 0xFFFFFF], &value, 4);
		return;
	}
	if(uint8_t* p = GetMemPtr(addr, 4, true)) {
		memcpy(p, &value, 4);
		return;
	}
	switch(addr >> 28) {
		case 0x4: case 0x5: WritePeriph(addr, value, 0xFFFFFFFF); return;
		case 0xD: WriteSio(addr, value); return;
		case 0xE: WritePpb(addr, value); return;
	}
	if((addr >> 24) == 0x18 || (addr >> 24) == 0x14 || (addr >> 24) == 0x15) {
		return;
	}
	char buf[64];
	snprintf(buf, sizeof(buf), "write32 to unmapped address %08X", addr);
	Fault(buf);
}

void Rp2040::Write16(uint32_t addr, uint16_t value)
{
	addr &= ~1u;
	if(uint8_t* p = GetMemPtr(addr, 2, true)) {
		p[0] = (uint8_t)value;
		p[1] = value >> 8;
		return;
	}
	//Peripherals: narrow writes are replicated across the 32-bit bus
	Write32(addr, value | (value << 16));
}

void Rp2040::Write8(uint32_t addr, uint8_t value)
{
	if(uint8_t* p = GetMemPtr(addr, 1, true)) {
		*p = value;
		return;
	}
	Write32(addr, value * 0x01010101u);
}

uint32_t Rp2040::ReadPeriph(uint32_t addr)
{
	uint32_t reg = addr & ~0x3000u; //strip atomic alias bits
	if((addr >> 28) == 5) {
		reg = addr & ~0x3000u;
	}

	switch(reg) {
		case 0x4000C008: return 0xFFFFFFFF; //RESETS: RESET_DONE
		case 0x40024004: return 0x80001000; //XOSC: STATUS stable + enabled
		case 0x40028000: case 0x4002C000: return Get(reg) | 0x80000000; //PLL: LOCK
		case 0x40060018: return 0x80000000; //ROSC: STATUS stable
		case 0x40058008: return 0; //WATCHDOG: REASON (not a watchdog reboot)

		//TIMER
		case 0x40054008: return _timerLatchHigh; //TIMEHR
		case 0x4005400C: { uint64_t t = TimeUs(Cores[_cur]); _timerLatchHigh = (uint32_t)(t >> 32); return (uint32_t)t; } //TIMELR
		case 0x40054024: return (uint32_t)(TimeUs(Cores[_cur]) >> 32); //TIMERAWH
		case 0x40054028: return (uint32_t)TimeUs(Cores[_cur]); //TIMERAWL
		case 0x40054020: return Get(reg) & 0x0F; //ARMED

		case 0x50200004: case 0x50300004: return 0x0F000F00; //PIO FSTAT: all TX/RX FIFOs empty
	}

	//CLOCKS: CLK_x_SELECTED registers (offset 8 in each 12-byte block, 10 clocks)
	if(reg >= 0x40008000 && reg < 0x40008078 && ((reg - 0x40008000) % 12) == 8) {
		//One-hot of the glitchless source currently selected in CTRL (clk_ref and clk_sys only)
		uint32_t ctrl = Get(reg - 8);
		if(reg == 0x40008038) return 1u << (ctrl & 3);
		if(reg == 0x40008044) return 1u << (ctrl & 1);
		return 1;
	}

	//DMA channel CTRL: never busy
	if(reg >= 0x50000000 && reg < 0x50000300 && (reg & 0x3F) == 0x0C) {
		return Get(reg) & ~(1u << 24);
	}

	return Get(reg);
}

void Rp2040::WritePeriph(uint32_t addr, uint32_t value, uint32_t mask)
{
	uint32_t alias = (addr >> 12) & 3;
	uint32_t reg = addr & ~0x3000u;
	uint32_t old = Get(reg);
	uint32_t nv;
	switch(alias) {
		default: case 0: nv = value; break;
		case 1: nv = old ^ value; break;
		case 2: nv = old | value; break;
		case 3: nv = old & ~value; break;
	}
	nv = (old & ~mask) | (nv & mask);

	//TIMER: INTR is write-1-to-clear, ALARMx writes arm the alarm
	if(reg == 0x40054034) {
		nv = old & ~value;
	} else if(reg >= 0x40054010 && reg <= 0x4005401C) {
		_periph[reg] = nv;
		_periph[0x40054020] = Get(0x40054020) | (1u << ((reg - 0x40054010) / 4));
		_alarmArmed = _periph[0x40054020];
		return;
	} else if(reg == 0x40054020) {
		nv = old & ~value; //ARMED: write 1 to disarm
		_alarmArmed = nv;
	}
	_periph[reg] = nv;
}

void Rp2040::UpdateTimerAlarms()
{
	uint32_t armed = Get(0x40054020);
	if(!armed) {
		return;
	}
	uint32_t now = (uint32_t)(_globalCycle / (CpuFreq / 1000000));
	for(int i = 0; i < 4; i++) {
		if(armed & (1 << i)) {
			uint32_t target = Get(0x40054010 + i * 4);
			if((int32_t)(now - target) >= 0) {
				armed &= ~(1 << i);
				_periph[0x40054034] = Get(0x40054034) | (1 << i); //INTR
				if(Get(0x40054038) & (1 << i)) { //INTE
					for(int core = 0; core < 2; core++) {
						Cores[core].NvicPending |= (1 << i); //TIMER_IRQ_0..3
					}
				}
			}
		}
	}
	_periph[0x40054020] = armed;
	_alarmArmed = armed;
}

uint32_t Rp2040::ReadSio(uint32_t addr)
{
	Core& c = Cores[_cur];
	uint32_t off = addr & 0xFFF;
	switch(off) {
		case 0x000: return _cur; //CPUID
		case 0x004: return 0; //GPIO_IN
		case 0x008: return 0; //GPIO_HI_IN
		case 0x050: return 0x02 | (_fifoToCore[_cur] ? 1 : 0); //FIFO_ST: RDY (+VLD)
		case 0x058: { uint32_t v = _fifoToCore[_cur]; _fifoToCore[_cur] = 0; return v; }
		case 0x05C: return _spinlocks; //SPINLOCK_ST
		case 0x060: return c.DivDividend;
		case 0x064: return c.DivDivisor;
		case 0x068: return c.DivDividend;
		case 0x06C: return c.DivDivisor;
		case 0x070: return c.DivQuotient;
		case 0x074: return c.DivRemainder;
		case 0x078: return 1; //DIV_CSR: READY, not DIRTY
	}
	if(off >= 0x100 && off < 0x180) {
		uint32_t bit = 1u << ((off - 0x100) / 4);
		if(_spinlocks & bit) {
			return 0;
		}
		_spinlocks |= bit;
		return bit;
	}
	if(off >= 0x080 && off < 0x100) {
		Fault("interpolator access not emulated");
		return 0;
	}
	return Get(addr);
}

void Rp2040::WriteSio(uint32_t addr, uint32_t value)
{
	Core& c = Cores[_cur];
	uint32_t off = addr & 0xFFF;
	auto udiv = [&]() {
		if(c.DivDivisor == 0) {
			c.DivQuotient = 0xFFFFFFFF;
			c.DivRemainder = c.DivDividend;
		} else {
			c.DivQuotient = c.DivDividend / c.DivDivisor;
			c.DivRemainder = c.DivDividend % c.DivDivisor;
		}
	};
	auto sdiv = [&]() {
		int32_t a = (int32_t)c.DivDividend, b = (int32_t)c.DivDivisor;
		if(b == 0) {
			c.DivQuotient = a < 0 ? 1 : 0xFFFFFFFF;
			c.DivRemainder = (uint32_t)a;
		} else if(a == INT32_MIN && b == -1) {
			c.DivQuotient = (uint32_t)INT32_MIN;
			c.DivRemainder = 0;
		} else {
			c.DivQuotient = (uint32_t)(a / b);
			c.DivRemainder = (uint32_t)(a % b);
		}
	};

	switch(off) {
		case 0x054: _fifoToCore[_cur ^ 1] = value; return; //FIFO_WR
		case 0x060: c.DivDividend = value; udiv(); return;
		case 0x064: c.DivDivisor = value; udiv(); return;
		case 0x068: c.DivDividend = value; sdiv(); return;
		case 0x06C: c.DivDivisor = value; sdiv(); return;
		case 0x070: c.DivQuotient = value; return;
		case 0x074: c.DivRemainder = value; return;
	}
	if(off >= 0x100 && off < 0x180) {
		_spinlocks &= ~(1u << ((off - 0x100) / 4));
		return;
	}
	if(off >= 0x080 && off < 0x100) {
		Fault("interpolator access not emulated");
		return;
	}
	_periph[addr] = value; //GPIO registers etc: ignored
}

uint32_t Rp2040::ReadPpb(uint32_t addr)
{
	Core& c = Cores[_cur];
	switch(addr) {
		case 0xE000ED00: return 0x410CC601; //CPUID: Cortex-M0+
		case 0xE000ED08: return c.Vtor;
		case 0xE000E100: case 0xE000E180: return c.NvicEnabled;
		case 0xE000E200: case 0xE000E280: return c.NvicPending;
	}
	return Get(addr + (_cur << 20));
}

void Rp2040::WritePpb(uint32_t addr, uint32_t value)
{
	Core& c = Cores[_cur];
	switch(addr) {
		case 0xE000ED08: c.Vtor = value & ~0xFFu; return;
		case 0xE000E100: c.NvicEnabled |= value; return;
		case 0xE000E180: c.NvicEnabled &= ~value; return;
		case 0xE000E200: c.NvicPending |= value; return;
		case 0xE000E280: c.NvicPending &= ~value; return;
	}
	_periph[addr + (_cur << 20)] = value;
}

// ---------------------------------------------------------------------------------------------
// CPU (ARMv6-M Thumb)
// ---------------------------------------------------------------------------------------------
uint32_t Rp2040::GetXpsr(Core& c)
{
	return (c.N << 31) | (c.Z << 30) | (c.C << 29) | (c.V << 28) | (1u << 24) | c.Ipsr;
}

void Rp2040::SetXpsr(Core& c, uint32_t v)
{
	c.N = (v >> 31) & 1;
	c.Z = (v >> 30) & 1;
	c.C = (v >> 29) & 1;
	c.V = (v >> 28) & 1;
}

uint32_t Rp2040::AddWithCarry(Core& c, uint32_t a, uint32_t b, bool carry, bool setFlags)
{
	uint64_t usum = (uint64_t)a + b + carry;
	uint32_t result = (uint32_t)usum;
	if(setFlags) {
		c.N = result >> 31;
		c.Z = result == 0;
		c.C = (usum >> 32) != 0;
		c.V = ((~(a ^ b) & (a ^ result)) >> 31) != 0;
	}
	return result;
}

bool Rp2040::CheckCond(Core& c, uint32_t cond)
{
	switch(cond) {
		case 0x0: return c.Z;
		case 0x1: return !c.Z;
		case 0x2: return c.C;
		case 0x3: return !c.C;
		case 0x4: return c.N;
		case 0x5: return !c.N;
		case 0x6: return c.V;
		case 0x7: return !c.V;
		case 0x8: return c.C && !c.Z;
		case 0x9: return !c.C || c.Z;
		case 0xA: return c.N == c.V;
		case 0xB: return c.N != c.V;
		case 0xC: return !c.Z && c.N == c.V;
		case 0xD: return c.Z || c.N != c.V;
		default: return true;
	}
}

void Rp2040::BranchWritePc(Core& c, uint32_t addr)
{
	c.R[15] = addr & ~1u;
	c.Cycles += 1;
}

void Rp2040::BxWritePc(Core& c, uint32_t addr)
{
	if(c.Ipsr != 0 && (addr & 0xF0000000) == 0xF0000000) {
		ExceptionReturn(c, addr);
		return;
	}
	if(!(addr & 1)) {
		char buf[64];
		snprintf(buf, sizeof(buf), "interworking branch to ARM state (%08X)", addr);
		Fault(buf);
		return;
	}
	c.R[15] = addr & ~1u;
	c.Cycles += 1;
}

void Rp2040::TakeException(Core& c, uint32_t num)
{
	uint32_t sp = c.R[13];
	bool align = (sp & 4) != 0;
	sp = (sp - 0x20) & ~7u;
	uint32_t xpsr = GetXpsr(c) | (align ? (1u << 9) : 0);
	Write32(sp + 0x00, c.R[0]);
	Write32(sp + 0x04, c.R[1]);
	Write32(sp + 0x08, c.R[2]);
	Write32(sp + 0x0C, c.R[3]);
	Write32(sp + 0x10, c.R[12]);
	Write32(sp + 0x14, c.R[14]);
	Write32(sp + 0x18, c.R[15]);
	Write32(sp + 0x1C, xpsr);
	c.R[13] = sp;
	c.R[14] = 0xFFFFFFF9;
	c.Ipsr = num;
	c.R[15] = Read32(c.Vtor + num * 4) & ~1u;
	c.Cycles += 16;
}

void Rp2040::ExceptionReturn(Core& c, uint32_t excReturn)
{
	(void)excReturn;
	uint32_t sp = c.R[13];
	c.R[0] = Read32(sp + 0x00);
	c.R[1] = Read32(sp + 0x04);
	c.R[2] = Read32(sp + 0x08);
	c.R[3] = Read32(sp + 0x0C);
	c.R[12] = Read32(sp + 0x10);
	c.R[14] = Read32(sp + 0x14);
	c.R[15] = Read32(sp + 0x18) & ~1u;
	uint32_t xpsr = Read32(sp + 0x1C);
	SetXpsr(c, xpsr);
	c.Ipsr = 0;
	c.R[13] = sp + 0x20 + ((xpsr & (1u << 9)) ? 4 : 0);
	c.Cycles += 16;
}

void Rp2040::CheckInterrupts(Core& c)
{
	uint32_t pending = c.NvicPending & c.NvicEnabled;
	if(!pending || c.Primask || c.Ipsr != 0) {
		return;
	}
	for(int i = 0; i < 32; i++) {
		if(pending & (1u << i)) {
			c.NvicPending &= ~(1u << i);
			TakeException(c, 16 + i);
			return;
		}
	}
}

void Rp2040::Step(Core& c)
{
	if(c.NvicPending) {
		CheckInterrupts(c);
	}

	uint32_t pc = c.R[15];

	//HLE hook check
	bool hookable;
	if(pc < 0x4000) {
		hookable = true;
	} else if((pc & 0xFF000000) == 0x10000000) {
		uint32_t idx = (pc & 0xFFFFFF) / 2;
		hookable = (_hookBits[idx >> 3] >> (idx & 7)) & 1;
	} else if((pc & 0xFF000000) == 0x20000000 && (pc & 0xFFFFFF) < SramSize) {
		uint32_t idx = (FlashSize + (pc & 0xFFFFFF)) / 2;
		hookable = (_hookBits[idx >> 3] >> (idx & 7)) & 1;
	} else {
		hookable = false;
	}
	if(hookable && (!_testNoHle || pc < 0x4000) && HandleHle(c, pc)) {
		return;
	}

	uint16_t op = Read16(pc);
	c.Cycles++;
	InstructionCount++;
	if((op >> 11) >= 0x1D) {
		uint16_t op2 = Read16(pc + 2);
		c.R[15] = pc + 4;
		Exec32(c, op, op2);
	} else {
		c.R[15] = pc + 2;
		Exec16(c, op);
	}
}

void Rp2040::Exec32(Core& c, uint16_t op1, uint16_t op2)
{
	uint32_t pc = c.R[15] - 4;
	if((op1 & 0xF800) == 0xF000 && (op2 & 0xD000) == 0xD000) {
		//BL
		uint32_t s = (op1 >> 10) & 1;
		uint32_t j1 = (op2 >> 13) & 1;
		uint32_t j2 = (op2 >> 11) & 1;
		uint32_t i1 = !(j1 ^ s);
		uint32_t i2 = !(j2 ^ s);
		uint32_t imm = (s << 24) | (i1 << 23) | (i2 << 22) | ((op1 & 0x3FF) << 12) | ((op2 & 0x7FF) << 1);
		if(s) {
			imm |= 0xFE000000;
		}
		c.R[14] = (pc + 4) | 1;
		c.R[15] = pc + 4 + imm;
		c.Cycles += 2;
		return;
	}

	if((op1 & 0xFFF0) == 0xF3E0 && (op2 & 0xF000) == 0x8000) {
		//MRS
		uint32_t rd = (op2 >> 8) & 0xF;
		uint32_t sysm = op2 & 0xFF;
		uint32_t v = 0;
		switch(sysm) {
			case 0: case 1: case 2: case 3: case 5: case 6: case 7: v = GetXpsr(c) & (sysm == 0 ? 0xF0000000 : 0xF00001FF); break;
			case 8: case 9: v = c.R[13]; break;
			case 16: v = c.Primask; break;
			case 20: v = 0; break; //CONTROL
		}
		if(sysm == 5 || sysm == 6 || sysm == 7 || sysm == 1 || sysm == 3) {
			v = (GetXpsr(c) & 0xF0000000) | c.Ipsr;
		}
		c.R[rd] = v;
		c.Cycles += 2;
		return;
	}

	if((op1 & 0xFFF0) == 0xF380 && (op2 & 0xFF00) == 0x8800) {
		//MSR
		uint32_t rn = op1 & 0xF;
		uint32_t sysm = op2 & 0xFF;
		uint32_t v = c.R[rn];
		switch(sysm) {
			case 0: case 1: case 2: case 3: SetXpsr(c, v); break;
			case 8: case 9: c.R[13] = v & ~3u; break;
			case 16: c.Primask = v & 1; break;
			case 20: break; //CONTROL
		}
		c.Cycles += 2;
		return;
	}

	if((op1 & 0xFFF0) == 0xF3B0 && (op2 & 0xFF00) == 0x8F00) {
		//DSB / DMB / ISB
		c.Cycles += 2;
		return;
	}

	char buf[64];
	snprintf(buf, sizeof(buf), "undefined 32-bit instruction %04X %04X at %08X", op1, op2, pc);
	Fault(buf);
}

void Rp2040::Exec16(Core& c, uint16_t op)
{
	uint32_t* R = c.R;
	auto reg = [&](uint32_t r) -> uint32_t { return r == 15 ? R[15] + 2 : R[r]; };

	switch(op >> 11) {
		case 0x00: { //LSL imm
			uint32_t imm = (op >> 6) & 0x1F, rm = R[(op >> 3) & 7], rd = op & 7;
			if(imm) {
				c.C = (rm >> (32 - imm)) & 1;
				rm <<= imm;
			}
			R[rd] = rm;
			SetNZ(c, rm);
			break;
		}
		case 0x01: { //LSR imm
			uint32_t imm = (op >> 6) & 0x1F, rm = R[(op >> 3) & 7], rd = op & 7;
			if(imm == 0) {
				c.C = rm >> 31;
				rm = 0;
			} else {
				c.C = (rm >> (imm - 1)) & 1;
				rm >>= imm;
			}
			R[rd] = rm;
			SetNZ(c, rm);
			break;
		}
		case 0x02: { //ASR imm
			uint32_t imm = (op >> 6) & 0x1F, rm = R[(op >> 3) & 7], rd = op & 7;
			if(imm == 0) {
				c.C = rm >> 31;
				rm = (int32_t)rm >> 31;
			} else {
				c.C = (rm >> (imm - 1)) & 1;
				rm = (uint32_t)((int32_t)rm >> imm);
			}
			R[rd] = rm;
			SetNZ(c, rm);
			break;
		}
		case 0x03: { //ADD/SUB reg/imm3
			uint32_t rd = op & 7, rn = R[(op >> 3) & 7];
			uint32_t v = (op & 0x400) ? ((op >> 6) & 7) : R[(op >> 6) & 7];
			if(op & 0x200) {
				R[rd] = AddWithCarry(c, rn, ~v, true, true);
			} else {
				R[rd] = AddWithCarry(c, rn, v, false, true);
			}
			break;
		}
		case 0x04: { uint32_t rd = (op >> 8) & 7; R[rd] = op & 0xFF; SetNZ(c, R[rd]); break; } //MOV imm
		case 0x05: { AddWithCarry(c, R[(op >> 8) & 7], ~(uint32_t)(op & 0xFF), true, true); break; } //CMP imm
		case 0x06: { uint32_t rd = (op >> 8) & 7; R[rd] = AddWithCarry(c, R[rd], op & 0xFF, false, true); break; } //ADD imm8
		case 0x07: { uint32_t rd = (op >> 8) & 7; R[rd] = AddWithCarry(c, R[rd], ~(uint32_t)(op & 0xFF), true, true); break; } //SUB imm8

		case 0x08: {
			if((op & 0x0400) == 0) {
				//Data processing
				uint32_t rdn = op & 7, rm = R[(op >> 3) & 7];
				uint32_t a = R[rdn];
				switch((op >> 6) & 0xF) {
					case 0x0: R[rdn] = a & rm; SetNZ(c, R[rdn]); break;
					case 0x1: R[rdn] = a ^ rm; SetNZ(c, R[rdn]); break;
					case 0x2: { //LSL reg
						uint32_t n = rm & 0xFF;
						if(n == 0) {
						} else if(n < 32) { c.C = (a >> (32 - n)) & 1; a <<= n; } else if(n == 32) { c.C = a & 1; a = 0; } else { c.C = 0; a = 0; }
						R[rdn] = a; SetNZ(c, a);
						break;
					}
					case 0x3: { //LSR reg
						uint32_t n = rm & 0xFF;
						if(n == 0) {
						} else if(n < 32) { c.C = (a >> (n - 1)) & 1; a >>= n; } else if(n == 32) { c.C = a >> 31; a = 0; } else { c.C = 0; a = 0; }
						R[rdn] = a; SetNZ(c, a);
						break;
					}
					case 0x4: { //ASR reg
						uint32_t n = rm & 0xFF;
						if(n == 0) {
						} else if(n < 32) { c.C = (a >> (n - 1)) & 1; a = (uint32_t)((int32_t)a >> n); } else { c.C = a >> 31; a = (uint32_t)((int32_t)a >> 31); }
						R[rdn] = a; SetNZ(c, a);
						break;
					}
					case 0x5: R[rdn] = AddWithCarry(c, a, rm, c.C, true); break; //ADC
					case 0x6: R[rdn] = AddWithCarry(c, a, ~rm, c.C, true); break; //SBC
					case 0x7: { //ROR
						uint32_t n = rm & 0xFF;
						if(n) {
							n &= 31;
							if(n) {
								a = (a >> n) | (a << (32 - n));
							}
							c.C = a >> 31;
						}
						R[rdn] = a; SetNZ(c, a);
						break;
					}
					case 0x8: SetNZ(c, a & rm); break; //TST
					case 0x9: R[rdn] = AddWithCarry(c, ~rm, 0, true, true); break; //RSB #0 (NEG)
					case 0xA: AddWithCarry(c, a, ~rm, true, true); break; //CMP
					case 0xB: AddWithCarry(c, a, rm, false, true); break; //CMN
					case 0xC: R[rdn] = a | rm; SetNZ(c, R[rdn]); break;
					case 0xD: R[rdn] = a * rm; SetNZ(c, R[rdn]); break; //MUL (single cycle on RP2040)
					case 0xE: R[rdn] = a & ~rm; SetNZ(c, R[rdn]); break;
					case 0xF: R[rdn] = ~rm; SetNZ(c, R[rdn]); break;
				}
			} else {
				//Special data / branch exchange
				uint32_t rm = (op >> 3) & 0xF;
				uint32_t rdn = (op & 7) | ((op >> 4) & 8);
				switch((op >> 8) & 3) {
					case 0: { //ADD (high)
						uint32_t v = reg(rdn) + reg(rm);
						if(rdn == 15) { BranchWritePc(c, v); } else { R[rdn] = v; }
						break;
					}
					case 1: AddWithCarry(c, reg(rdn), ~reg(rm), true, true); break; //CMP (high)
					case 2: { //MOV (high)
						uint32_t v = reg(rm);
						if(rdn == 15) { BranchWritePc(c, v); } else { R[rdn] = v; }
						break;
					}
					case 3: { //BX / BLX
						uint32_t target = reg(rm);
						if(op & 0x80) {
							R[14] = R[15] | 1;
						}
						BxWritePc(c, target);
						break;
					}
				}
			}
			break;
		}

		case 0x09: { //LDR literal
			uint32_t addr = ((R[15] + 2) & ~3u) + (op & 0xFF) * 4;
			R[(op >> 8) & 7] = Read32(addr);
			c.Cycles++;
			break;
		}

		case 0x0A: case 0x0B: { //Load/store register offset
			uint32_t rt = op & 7;
			uint32_t addr = R[(op >> 3) & 7] + R[(op >> 6) & 7];
			switch((op >> 9) & 7) {
				case 0: Write32(addr, R[rt]); break;
				case 1: Write16(addr, (uint16_t)R[rt]); break;
				case 2: Write8(addr, (uint8_t)R[rt]); break;
				case 3: R[rt] = (uint32_t)(int8_t)Read8(addr); break;
				case 4: R[rt] = Read32(addr); break;
				case 5: R[rt] = Read16(addr); break;
				case 6: R[rt] = Read8(addr); break;
				case 7: R[rt] = (uint32_t)(int16_t)Read16(addr); break;
			}
			c.Cycles++;
			break;
		}

		case 0x0C: Write32(R[(op >> 3) & 7] + ((op >> 6) & 0x1F) * 4, R[op & 7]); c.Cycles++; break;
		case 0x0D: R[op & 7] = Read32(R[(op >> 3) & 7] + ((op >> 6) & 0x1F) * 4); c.Cycles++; break;
		case 0x0E: Write8(R[(op >> 3) & 7] + ((op >> 6) & 0x1F), (uint8_t)R[op & 7]); c.Cycles++; break;
		case 0x0F: R[op & 7] = Read8(R[(op >> 3) & 7] + ((op >> 6) & 0x1F)); c.Cycles++; break;
		case 0x10: Write16(R[(op >> 3) & 7] + ((op >> 6) & 0x1F) * 2, (uint16_t)R[op & 7]); c.Cycles++; break;
		case 0x11: R[op & 7] = Read16(R[(op >> 3) & 7] + ((op >> 6) & 0x1F) * 2); c.Cycles++; break;
		case 0x12: Write32(R[13] + (op & 0xFF) * 4, R[(op >> 8) & 7]); c.Cycles++; break;
		case 0x13: R[(op >> 8) & 7] = Read32(R[13] + (op & 0xFF) * 4); c.Cycles++; break;
		case 0x14: R[(op >> 8) & 7] = ((R[15] + 2) & ~3u) + (op & 0xFF) * 4; break; //ADR
		case 0x15: R[(op >> 8) & 7] = R[13] + (op & 0xFF) * 4; break; //ADD Rd, SP, imm

		case 0x16: case 0x17: { //Miscellaneous
			if((op & 0xFF00) == 0xB000) {
				if(op & 0x80) {
					R[13] -= (op & 0x7F) * 4;
				} else {
					R[13] += (op & 0x7F) * 4;
				}
			} else if((op & 0xFF00) == 0xB200) {
				uint32_t rm = R[(op >> 3) & 7], rd = op & 7;
				switch((op >> 6) & 3) {
					case 0: R[rd] = (uint32_t)(int16_t)rm; break;
					case 1: R[rd] = (uint32_t)(int8_t)rm; break;
					case 2: R[rd] = rm & 0xFFFF; break;
					case 3: R[rd] = rm & 0xFF; break;
				}
			} else if((op & 0xFE00) == 0xB400) { //PUSH
				uint32_t list = op & 0xFF;
				bool lr = (op & 0x100) != 0;
				int count = PopCount32(list) + (lr ? 1 : 0);
				uint32_t addr = R[13] - count * 4;
				R[13] = addr;
				for(int i = 0; i < 8; i++) {
					if(list & (1 << i)) {
						Write32(addr, R[i]);
						addr += 4;
					}
				}
				if(lr) {
					Write32(addr, R[14]);
				}
				c.Cycles += count;
			} else if((op & 0xFFEF) == 0xB662) { //CPS
				c.Primask = (op & 0x10) != 0;
			} else if((op & 0xFF00) == 0xBA00) {
				uint32_t rm = R[(op >> 3) & 7], rd = op & 7;
				switch((op >> 6) & 3) {
					case 0: R[rd] = ByteSwap32(rm); break;
					case 1: R[rd] = ((rm & 0x00FF00FF) << 8) | ((rm & 0xFF00FF00) >> 8); break;
					case 3: R[rd] = (uint32_t)(int16_t)(((rm & 0xFF) << 8) | ((rm >> 8) & 0xFF)); break;
					default: Fault("undefined REV variant"); break;
				}
			} else if((op & 0xFE00) == 0xBC00) { //POP
				uint32_t list = op & 0xFF;
				bool pcBit = (op & 0x100) != 0;
				uint32_t addr = R[13];
				int count = PopCount32(list) + (pcBit ? 1 : 0);
				R[13] = addr + count * 4;
				for(int i = 0; i < 8; i++) {
					if(list & (1 << i)) {
						R[i] = Read32(addr);
						addr += 4;
					}
				}
				c.Cycles += count;
				if(pcBit) {
					BxWritePc(c, Read32(addr));
				}
			} else if((op & 0xFF00) == 0xBE00) { //BKPT
				char buf[48];
				snprintf(buf, sizeof(buf), "BKPT #%d", op & 0xFF);
				Fault(buf);
			} else if((op & 0xFF00) == 0xBF00) { //Hints
				switch((op >> 4) & 0xF) {
					case 2: case 3: c.Cycles += 32; break; //WFE/WFI: let time pass (other core / timer)
					default: break;
				}
			} else {
				char buf[64];
				snprintf(buf, sizeof(buf), "undefined instruction %04X", op);
				Fault(buf);
			}
			break;
		}

		case 0x18: { //STMIA
			uint32_t rn = (op >> 8) & 7;
			uint32_t addr = R[rn];
			for(int i = 0; i < 8; i++) {
				if(op & (1 << i)) {
					Write32(addr, R[i]);
					addr += 4;
					c.Cycles++;
				}
			}
			R[rn] = addr;
			break;
		}
		case 0x19: { //LDMIA
			uint32_t rn = (op >> 8) & 7;
			uint32_t addr = R[rn];
			for(int i = 0; i < 8; i++) {
				if(op & (1 << i)) {
					R[i] = Read32(addr);
					addr += 4;
					c.Cycles++;
				}
			}
			if(!(op & (1 << rn))) {
				R[rn] = addr;
			}
			break;
		}

		case 0x1A: case 0x1B: { //Bcc / SVC / UDF
			uint32_t cond = (op >> 8) & 0xF;
			if(cond == 0xF) {
				Fault("SVC not supported");
			} else if(cond == 0xE) {
				Fault("UDF");
			} else if(CheckCond(c, cond)) {
				BranchWritePc(c, R[15] + 2 + ((int32_t)(int8_t)(op & 0xFF) << 1));
			}
			break;
		}

		case 0x1C: { //B
			int32_t imm = (op & 0x7FF) << 1;
			if(imm & 0x800) {
				imm |= ~0xFFF;
			}
			BranchWritePc(c, R[15] + 2 + imm);
			break;
		}

		default: {
			char buf[64];
			snprintf(buf, sizeof(buf), "undefined instruction %04X", op);
			Fault(buf);
			break;
		}
	}
}

// ---------------------------------------------------------------------------------------------
// HLE
// ---------------------------------------------------------------------------------------------
void Rp2040::HleReturn(Core& c, uint32_t r0)
{
	c.R[0] = r0;
	c.InHle = false;
	c.HleProgress = 0;
	c.R[15] = c.R[14] & ~1u;
	c.Cycles += 4;
}

void Rp2040::HleReturn64(Core& c, uint64_t v)
{
	c.R[1] = (uint32_t)(v >> 32);
	HleReturn(c, (uint32_t)v);
}

std::string Rp2040::ReadCString(uint32_t addr, size_t max)
{
	std::string s;
	for(size_t i = 0; i < max; i++) {
		uint8_t ch = Read8(addr + (uint32_t)i);
		if(!ch) {
			break;
		}
		s += (char)ch;
	}
	return s;
}

std::string Rp2040::FormatPrintf(Core& c, uint32_t fmtAddr, int firstArg)
{
	std::string fmt = ReadCString(fmtAddr, 512);
	std::string out;
	int argIdx = firstArg;
	auto nextArg = [&]() -> uint32_t {
		uint32_t v = argIdx < 4 ? c.R[argIdx] : Read32(c.R[13] + (argIdx - 4) * 4);
		argIdx++;
		return v;
	};
	for(size_t i = 0; i < fmt.size(); i++) {
		if(fmt[i] != '%') {
			out += fmt[i];
			continue;
		}
		std::string spec = "%";
		i++;
		while(i < fmt.size() && strchr("-+ #0123456789.l", fmt[i])) {
			if(fmt[i] != 'l') {
				spec += fmt[i];
			}
			i++;
		}
		if(i >= fmt.size()) {
			break;
		}
		char conv = fmt[i];
		char buf[256];
		switch(conv) {
			case 'd': case 'i': snprintf(buf, sizeof(buf), (spec + "d").c_str(), (int32_t)nextArg()); out += buf; break;
			case 'u': case 'x': case 'X': case 'o': snprintf(buf, sizeof(buf), (spec + conv).c_str(), nextArg()); out += buf; break;
			case 'c': out += (char)nextArg(); break;
			case 's': out += ReadCString(nextArg()); break;
			case 'p': snprintf(buf, sizeof(buf), "%08X", nextArg()); out += buf; break;
			case '%': out += '%'; break;
			default: out += spec + conv; break;
		}
	}
	return out;
}

bool Rp2040::HandleHle(Core& c, uint32_t pc)
{
	int id;
	if(pc < 0x4000) {
		if(pc >= BootRomFuncBase && pc < BootRomFuncBase + 0x800) {
			HleBootRomFunc(c, pc);
			return true;
		}
		auto it = _hooks.find(pc);
		if(it == _hooks.end()) {
			char buf[64];
			snprintf(buf, sizeof(buf), "execution in bootrom at %04X", pc);
			Fault(buf);
			return true;
		}
		id = it->second;
	} else {
		auto it = _hooks.find(pc);
		if(it == _hooks.end()) {
			return false;
		}
		id = it->second;
	}

	HleResult r = RunHook(c, id);
	if(r == HleResult::Stall) {
		//Keep PC on the hooked function and let time pass; it will be retried
		c.InHle = true;
		//Nothing the hook waits for can change before the end of the current slice (SNES accesses happen between
		//RunUntil() calls, the other core only runs between slices), so skip ahead to the end of the slice or the deadline
		uint64_t target = _sliceTarget;
		if(c.HleDeadline && c.HleDeadline < target) {
			target = c.HleDeadline;
		}
		c.Cycles = std::max(c.Cycles + 1, target);
		return true;
	}
	return r != HleResult::Continue;
}

Rp2040::HleResult Rp2040::RunHook(Core& c, int id)
{
	using namespace XcHook;
	uint32_t* R = c.R;

	switch(id) {
		case SetSysClockPll:
		case StdioInitAll:
		case BusInit:
			HleReturn(c, 0);
			return HleResult::Return;

		case Puts:
			if(Log) {
				Log("[RP2040] " + ReadCString(R[0]));
			}
			HleReturn(c, 0);
			return HleResult::Return;

		case Printf: {
			std::string s = FormatPrintf(c, R[0], 1);
			while(!s.empty() && (s.back() == '\n' || s.back() == '\r')) {
				s.pop_back();
			}
			if(Log) {
				Log("[RP2040] " + s);
			}
			HleReturn(c, (uint32_t)s.size());
			return HleResult::Return;
		}

		case Panic:
			Fault("panic: " + FormatPrintf(c, R[0], 1));
			return HleResult::Return;

		case LaunchCore1: {
			Core& c1 = Cores[1];
			c1 = Core();
			c1.R[13] = 0x20041000; //SCRATCH_X top (stack bottom 0x20040800 + 0x800)
			c1.R[15] = R[0] & ~1u;
			c1.R[14] = Core1ExitAddr | 1;
			c1.Vtor = c.Vtor;
			c1.Cycles = c.Cycles;
			c1.Running = true;
			HleReturn(c, 0);
			return HleResult::Return;
		}

		case Core1Exit:
			c.Running = false;
			return HleResult::Return;

		case SleepUntil: {
			uint64_t t = ((uint64_t)R[1] << 32) | R[0];
			if(TimeUs(c) >= t) {
				c.HleDeadline = 0;
				HleReturn(c, 0);
				return HleResult::Return;
			}
			c.HleDeadline = t * (CpuFreq / 1000000);
			return HleResult::Stall;
		}

		case BusFlush:
			TxFifo.clear();
			RxFifo.clear();
			HleReturn(c, 0);
			return HleResult::Return;

		case BusWaitTx:
			if(TxFifo.size() > TxFifoDepth) {
				return HleResult::Stall;
			}
			HleReturn(c, 0);
			return HleResult::Return;

		case BusSend: {
			//r1 = buffer descriptor: +0 base, +8 offset, +0xC length
			uint32_t buf = R[1];
			uint32_t len = Read32(buf + 0xC);
			if(len == 0) {
				HleReturn(c, 0);
				return HleResult::Return;
			}
			if(TxFifo.size() > TxFifoDepth) {
				return HleResult::Stall; //previous DMA transfer still running
			}
			uint32_t base = Read32(buf);
			uint32_t off = Read32(buf + 8);
			for(uint32_t i = 0; i < len; i++) {
				TxFifo.push_back(Read8(base + off + i));
			}
			Write32(buf + 8, off + len + 16 - (len & 15));
			Write32(buf + 0xC, 0);
			HleReturn(c, 0);
			return HleResult::Return;
		}

		case BusRecv: {
			//r1 = dest, r2 = count, r3 = timeout in ms (-1 = forever); returns bytes received
			uint32_t dst = R[1], count = R[2], timeout = R[3];
			if(!c.InHle) {
				c.HleProgress = 0;
				c.HleDeadline = timeout == 0xFFFFFFFF ? 0 : c.Cycles + (uint64_t)timeout * (CpuFreq / 1000);
			}
			while(c.HleProgress < count && !RxFifo.empty()) {
				Write8(dst + c.HleProgress, RxFifo.front());
				RxFifo.pop_front();
				c.HleProgress++;
			}
			if(c.HleProgress >= count || (c.HleDeadline && c.Cycles >= c.HleDeadline)) {
				uint32_t got = c.HleProgress;
				c.HleDeadline = 0;
				HleReturn(c, got);
				return HleResult::Return;
			}
			return HleResult::Stall;
		}

		case BusPush: {
			uint32_t src = R[1], count = R[2];
			for(uint32_t i = 0; i < count; i++) {
				TxFifo.push_back(Read8(src + i));
			}
			HleReturn(c, 0);
			return HleResult::Return;
		}

		case FlashErase: {
			uint32_t off = R[0], count = R[1];
			if(off + count <= FlashSize) {
				memset(&Flash[off], 0xFF, count);
				if(off + count > SaveOffset) {
					SaveDirty = true;
				}
			}
			HleReturn(c, 0);
			return HleResult::Return;
		}

		case FlashProgram: {
			uint32_t off = R[0], src = R[1], count = R[2];
			if(off + count <= FlashSize) {
				for(uint32_t i = 0; i < count; i++) {
					Flash[off + i] &= Read8(src + i); //NOR flash: program can only clear bits
				}
				if(off + count > SaveOffset) {
					SaveDirty = true;
				}
			}
			HleReturn(c, 0);
			return HleResult::Return;
		}

		case FlashDoCmd: {
			uint32_t tx = R[0], rx = R[1], count = R[2];
			uint8_t cmd = count ? Read8(tx) : 0;
			static const uint8_t uniqueId[8] = { 0xE6, 0x60, 0x58, 0x38, 0x83, 0x2B, 0x44, 0x2A };
			static const uint8_t jedec[3] = { 0xEF, 0x40, 0x18 }; //W25Q128
			for(uint32_t i = 0; i < count; i++) {
				uint8_t v = 0;
				if(cmd == 0x4B && i >= 5 && i < 13) v = uniqueId[i - 5];
				else if(cmd == 0x9F && i >= 1 && i < 4) v = jedec[i - 1];
				Write8(rx + i, v);
			}
			HleReturn(c, 0);
			return HleResult::Return;
		}

		case BrrEncode:
			HleBrrEncode(c);
			return HleResult::Return;

		case BootRomLookup: {
			//rom_table_lookup(uint16_t* table, uint32_t code)
			uint32_t table = R[0], code = R[1];
			for(int i = 0; i < 64; i++) {
				uint16_t entryCode = Read16(table + i * 4);
				if(entryCode == 0) {
					break;
				}
				if(entryCode == code) {
					HleReturn(c, Read16(table + i * 4 + 2));
					return HleResult::Return;
				}
			}
			if(Log) {
				char buf[64];
				snprintf(buf, sizeof(buf), "RP2040: unknown bootrom lookup '%c%c'", code & 0xFF, (code >> 8) & 0xFF);
				Log(buf);
			}
			HleReturn(c, 0);
			return HleResult::Return;
		}
	}
	return HleResult::Continue;
}

// Native version of the firmware's BRR encoder (RAM function at 0x20000A00), bit-exact with the original:
//   void encode(unused, const int32_t* src, uint8_t* dst, unused, int stride)
// Reads 16 samples (low 16 bits of every stride-th word), tries shift 12..2 with filter 0, keeps the shift with the
// lowest squared error (32-bit wrapping arithmetic, signed compares, first best wins) and writes a 9-byte BRR block
// with the loop flag set.
void Rp2040::HleBrrEncode(Core& c)
{
	uint32_t src = c.R[1];
	uint32_t dst = c.R[2];
	uint32_t stride = Read32(c.R[13]);

	int16_t samples[16];
	for(int i = 0; i < 16; i++) {
		samples[i] = (int16_t)Read32(src + i * stride * 4);
	}

	//Stack frame of the original function (used only if no shift is ever selected, to reproduce what it would copy)
	uint32_t frame = c.R[13] - 0x14 - 0x5C;
	uint8_t out[9];
	for(int i = 0; i < 9; i++) {
		out[i] = Read8(frame + 0x1C + i);
	}

	int32_t bestErr = 0x7FFFFFFF;
	bool found = false;
	uint8_t header = 0;
	uint8_t nib[16];
	for(int shift = 12; shift != 1; shift--) {
		uint32_t half = (uint32_t)(1 << shift) >> 1;
		uint32_t err = 0;
		for(int i = 0; i < 16; i++) {
			int32_t r7 = (int32_t)samples[i] >> 1;
			int32_t p = (int32_t)((((uint32_t)r7 << 17) >> 16) + half) >> shift;
			if(p > 7) {
				p = 7;
			}
			int32_t n = (int32_t)((((uint32_t)r7 | 0xFFFF8000u) << 1) + half) >> shift;
			if(n + 8 >= 0) {
				if(n > 7) {
					n = 7;
				}
			} else {
				n = -8;
			}
			int32_t recP = (int32_t)(int16_t)(((uint32_t)p << shift) & ~1u) >> 1;
			int32_t recN = (int32_t)(int16_t)(((uint32_t)n << shift) & ~1u) >> 1;
			int32_t eP = r7 - recP;
			int32_t eN = r7 - recN;
			int32_t sqP = (int32_t)((uint32_t)eP * (uint32_t)eP);
			int32_t sqN = (int32_t)((uint32_t)eN * (uint32_t)eN);
			if(sqP < sqN) {
				err += (uint32_t)sqP;
				nib[i] = (uint8_t)p;
			} else {
				err += (uint32_t)sqN;
				nib[i] = (uint8_t)(n & 0x0F);
			}
		}
		if((int32_t)err < bestErr) {
			header = (uint8_t)(shift << 4);
			for(int k = 0; k < 8; k++) {
				out[1 + k] = (uint8_t)((nib[k * 2] << 4) | nib[k * 2 + 1]);
			}
			found = true;
			bestErr = (int32_t)err;
		}
	}
	if(found) {
		out[0] = header;
	}
	out[0] |= 0x02;
	for(int i = 0; i < 9; i++) {
		Write8(dst + i, out[i]);
	}
	c.Cycles += BrrEncodeCycles;
	HleReturn(c, c.R[0]);
}

static float AsFloat(uint32_t v) { float f; memcpy(&f, &v, 4); return f; }
static uint32_t FromFloat(float f) { uint32_t v; memcpy(&v, &f, 4); return v; }
static double AsDouble(uint32_t lo, uint32_t hi) { uint64_t v = ((uint64_t)hi << 32) | lo; double d; memcpy(&d, &v, 8); return d; }
static uint64_t FromDouble(double d) { uint64_t v; memcpy(&v, &d, 8); return v; }

template<typename TOut, typename TIn>
static TOut SatCast(TIn v)
{
	if(std::isnan(v)) {
		return 0;
	}
	if(v <= (TIn)std::numeric_limits<TOut>::min()) {
		return std::numeric_limits<TOut>::min();
	}
	if(v >= (TIn)std::numeric_limits<TOut>::max()) {
		return std::numeric_limits<TOut>::max();
	}
	return (TOut)v;
}

void Rp2040::HleBootRomFunc(Core& c, uint32_t pc)
{
	uint32_t* R = c.R;
	if(pc >= BootRomFuncBase && pc < BootRomFloatBase) {
		uint32_t idx = (pc - BootRomFuncBase) / 4;
		std::string code = idx < sizeof(BootRomFuncCodes) / sizeof(BootRomFuncCodes[0]) ? BootRomFuncCodes[idx] : "??";
		if(code == "P3") { HleReturn(c, PopCount32(R[0])); return; }
		if(code == "R3") { uint32_t v = R[0], r = 0; for(int i = 0; i < 32; i++) { r = (r << 1) | ((v >> i) & 1); } HleReturn(c, r); return; }
		if(code == "L3") { HleReturn(c, CountLeadingZeros32(R[0])); return; }
		if(code == "T3") { HleReturn(c, CountTrailingZeros32(R[0])); return; }
		if(code == "MS" || code == "S4") {
			uint32_t dst = R[0];
			for(uint32_t i = 0; i < R[2]; i++) {
				Write8(dst + i, (uint8_t)R[1]);
			}
			c.Cycles += R[2] / 4;
			HleReturn(c, dst);
			return;
		}
		if(code == "MC" || code == "C4") {
			uint32_t dst = R[0], src = R[1], n = R[2];
			for(uint32_t i = 0; i < n; i++) {
				Write8(dst + i, Read8(src + i));
			}
			c.Cycles += n / 2;
			HleReturn(c, dst);
			return;
		}
		if(code == "IF" || code == "EX" || code == "FC" || code == "CX") { HleReturn(c, 0); return; }
		Fault("unsupported bootrom function " + code);
		return;
	}

	if(pc >= BootRomFloatBase && pc < BootRomDoubleBase) {
		uint32_t off = pc - BootRomFloatBase;
		float a = AsFloat(R[0]), b = AsFloat(R[1]);
		c.Cycles += 40;
		switch(off) {
			case 0x00: HleReturn(c, FromFloat(a + b)); return;
			case 0x04: HleReturn(c, FromFloat(a - b)); return;
			case 0x08: HleReturn(c, FromFloat(a * b)); return;
			case 0x0C: HleReturn(c, FromFloat(a / b)); return;
			case 0x10: case 0x54: { //fcmp: -1, 0, 1
				int r = (std::isnan(a) || std::isnan(b)) ? 1 : (a < b ? -1 : (a > b ? 1 : 0));
				HleReturn(c, (uint32_t)r);
				return;
			}
			case 0x14: { //fcmp_fast_flags: flags as for CMP a,b
				bool un = std::isnan(a) || std::isnan(b);
				c.N = !un && a < b; c.Z = !un && a == b; c.C = un || a >= b; c.V = un;
				HleReturn(c, R[0]);
				return;
			}
			case 0x18: HleReturn(c, FromFloat(std::sqrt(a))); return;
			case 0x1C: HleReturn(c, (uint32_t)SatCast<int32_t>((double)a)); return;
			case 0x20: HleReturn(c, (uint32_t)SatCast<int32_t>(std::ldexp((double)a, (int)R[1]))); return;
			case 0x24: HleReturn(c, SatCast<uint32_t>((double)a)); return;
			case 0x28: HleReturn(c, SatCast<uint32_t>(std::ldexp((double)a, (int)R[1]))); return;
			case 0x2C: HleReturn(c, FromFloat((float)(int32_t)R[0])); return;
			case 0x30: HleReturn(c, FromFloat((float)std::ldexp((double)(int32_t)R[0], -(int)R[1]))); return;
			case 0x34: HleReturn(c, FromFloat((float)R[0])); return;
			case 0x38: HleReturn(c, FromFloat((float)std::ldexp((double)R[0], -(int)R[1]))); return;
			case 0x3C: HleReturn(c, FromFloat(std::cos(a))); return;
			case 0x40: HleReturn(c, FromFloat(std::sin(a))); return;
			case 0x44: HleReturn(c, FromFloat(std::tan(a))); return;
			case 0x4C: HleReturn(c, FromFloat(std::exp(a))); return;
			case 0x50: HleReturn(c, FromFloat(std::log(a))); return;
			case 0x58: HleReturn(c, FromFloat(std::atan2(a, b))); return;
			case 0x5C: HleReturn(c, FromFloat((float)(int64_t)(((uint64_t)R[1] << 32) | R[0]))); return;
			case 0x64: HleReturn(c, FromFloat((float)(((uint64_t)R[1] << 32) | R[0]))); return;
			case 0x6C: HleReturn64(c, (uint64_t)SatCast<int64_t>((double)a)); return;
			case 0x74: HleReturn64(c, SatCast<uint64_t>((double)a)); return;
			case 0x7C: HleReturn64(c, FromDouble((double)a)); return;
		}
		char buf[64];
		snprintf(buf, sizeof(buf), "unsupported soft-float table entry +%02X", off);
		Fault(buf);
		return;
	}

	if(pc >= BootRomDoubleBase && pc < BootRomDoubleBase + 0x200) {
		uint32_t off = pc - BootRomDoubleBase;
		double a = AsDouble(R[0], R[1]), b = AsDouble(R[2], R[3]);
		c.Cycles += 80;
		switch(off) {
			case 0x00: HleReturn64(c, FromDouble(a + b)); return;
			case 0x04: HleReturn64(c, FromDouble(a - b)); return;
			case 0x08: HleReturn64(c, FromDouble(a * b)); return;
			case 0x0C: HleReturn64(c, FromDouble(a / b)); return;
			case 0x10: case 0x54: {
				int r = (std::isnan(a) || std::isnan(b)) ? 1 : (a < b ? -1 : (a > b ? 1 : 0));
				HleReturn(c, (uint32_t)r);
				return;
			}
			case 0x18: HleReturn64(c, FromDouble(std::sqrt(a))); return;
			case 0x1C: HleReturn(c, (uint32_t)SatCast<int32_t>(a)); return;
			case 0x24: HleReturn(c, SatCast<uint32_t>(a)); return;
			case 0x2C: HleReturn64(c, FromDouble((double)(int32_t)R[0])); return;
			case 0x34: HleReturn64(c, FromDouble((double)R[0])); return;
			case 0x3C: HleReturn64(c, FromDouble(std::cos(a))); return;
			case 0x40: HleReturn64(c, FromDouble(std::sin(a))); return;
			case 0x44: HleReturn64(c, FromDouble(std::tan(a))); return;
			case 0x4C: HleReturn64(c, FromDouble(std::exp(a))); return;
			case 0x50: HleReturn64(c, FromDouble(std::log(a))); return;
			case 0x58: HleReturn64(c, FromDouble(std::atan2(a, b))); return;
			case 0x7C: HleReturn(c, FromFloat((float)a)); return;
		}
		char buf[64];
		snprintf(buf, sizeof(buf), "unsupported soft-double table entry +%02X", off);
		Fault(buf);
		return;
	}
}
