#pragma once
// Minimal RP2040 emulator for the Xeno Crisis (Bitmap Bureau) SNES cartridge.
// Two ARMv6-M (Cortex-M0+) Thumb cores, 264KB SRAM, 16MB XIP flash image, synthetic bootrom,
// just enough peripherals for pico-sdk runtime init, plus HLE of the firmware's SNES bus layer.
// No emulator-specific dependencies so it can be unit-tested standalone.
#include <cstdint>
#include <cstring>
#include <vector>
#include <deque>
#include <string>
#include <functional>
#include <unordered_map>
#include <limits>

class Rp2040
{
public:
	static constexpr uint32_t FlashSize = 0x1000000;
	static constexpr uint32_t SramSize = 0x42000;
	static constexpr uint32_t BootRomSize = 0x4000;
	static constexpr uint32_t SaveOffset = 0xFF8000; //4 x 4KB wear-levelled save sectors used by the firmware
	static constexpr uint32_t SaveSize = 0x8000;
	static constexpr uint64_t CpuFreq = 133000000;
	static constexpr size_t TxFifoDepth = 8; //PIO TX FIFO (joined)
	static constexpr uint32_t BrrEncodeCycles = 10900; //average cost of the interpreted encoder (measured with CallForTest)

	//Debug/test helper: call a firmware function on core 0 with HLE hooks optionally disabled, returns r0
	uint32_t CallForTest(uint32_t addr, const std::vector<uint32_t>& args, bool allowHle, uint64_t* cycles = nullptr);

	struct Core
	{
		uint32_t R[16] = {};
		bool N = false, Z = false, C = false, V = false;
		bool Primask = false;
		uint32_t Ipsr = 0;
		uint64_t Cycles = 0;
		bool Running = false;
		//HLE stall state (function called but waiting on an external event)
		bool InHle = false;
		uint64_t HleDeadline = 0;
		uint32_t HleProgress = 0;
		//SIO hardware divider
		uint32_t DivDividend = 0, DivDivisor = 0, DivQuotient = 0, DivRemainder = 0;
		//NVIC
		uint32_t NvicEnabled = 0, NvicPending = 0;
		uint32_t Vtor = 0;
	};

	Core Cores[2];
	std::vector<uint8_t> Flash;
	std::vector<uint8_t> Sram;
	std::vector<uint8_t> BootRom;
	std::vector<uint8_t> UsbRam;

	//SNES <-> RP2040 byte streams (the $3000 window)
	std::deque<uint8_t> TxFifo; //RP2040 -> SNES (read from $3000)
	std::deque<uint8_t> RxFifo; //SNES -> RP2040 (written to $3000)

	bool SaveDirty = false;
	std::function<void(const std::string&)> Log;

	Rp2040();
	bool LoadFlash(const uint8_t* data, size_t size, std::string& error);
	void PowerOn();

	//Runs both cores until the given RP2040 cycle count is reached
	void RunUntil(uint64_t cycle);
	uint64_t GetCycle() { return _globalCycle; }

	//Save states: everything except the read-only part of flash (the save area is included)
	void SaveState(std::vector<uint8_t>& out);
	bool LoadState(const std::vector<uint8_t>& in);

	uint8_t SnesRead();
	void SnesWrite(uint8_t value);

	uint64_t InstructionCount = 0;
	bool Faulted = false;
	std::string FaultMessage;

private:
	uint64_t _globalCycle = 0;
	std::unordered_map<uint32_t, uint32_t> _periph;
	uint32_t _spinlocks = 0;
	uint32_t _fifoToCore[2] = {};
	int _cur = 0; //core currently executing

	enum class HleResult { Return, Stall, Continue };
	std::unordered_map<uint32_t, int> _hooks;
	std::vector<uint8_t> _hookBits;
	uint32_t _timerLatchHigh = 0;
	bool _testNoHle = false;
	uint64_t _sliceTarget = 0;
	uint32_t _alarmArmed = 0;
	static constexpr uint64_t SliceCycles = 512;

	void AddHook(uint32_t addr, int id);
	void UpdateTimerAlarms();
	uint32_t Get(uint32_t reg) { auto it = _periph.find(reg); return it == _periph.end() ? 0 : it->second; }

	void BuildBootRom();
	void InstallHooks();
	void Fault(const std::string& msg);

	uint32_t Read32(uint32_t addr);
	uint16_t Read16(uint32_t addr);
	uint8_t Read8(uint32_t addr);
	void Write32(uint32_t addr, uint32_t value);
	void Write16(uint32_t addr, uint16_t value);
	void Write8(uint32_t addr, uint8_t value);

	uint32_t ReadPeriph(uint32_t addr);
	void WritePeriph(uint32_t addr, uint32_t value, uint32_t mask);
	uint32_t ReadSio(uint32_t addr);
	void WriteSio(uint32_t addr, uint32_t value);
	uint32_t ReadPpb(uint32_t addr);
	void WritePpb(uint32_t addr, uint32_t value);

	uint8_t* GetMemPtr(uint32_t addr, uint32_t size, bool write);

	void RunCore(int id, uint64_t target);
	void Step(Core& c);
	void Exec16(Core& c, uint16_t op);
	void Exec32(Core& c, uint16_t op1, uint16_t op2);
	bool CheckCond(Core& c, uint32_t cond);
	void BranchWritePc(Core& c, uint32_t addr);
	void BxWritePc(Core& c, uint32_t addr);
	uint32_t AddWithCarry(Core& c, uint32_t a, uint32_t b, bool carry, bool setFlags);
	void SetNZ(Core& c, uint32_t v) { c.N = (v >> 31) != 0; c.Z = v == 0; }
	uint32_t GetXpsr(Core& c);
	void SetXpsr(Core& c, uint32_t v);
	void TakeException(Core& c, uint32_t num);
	void ExceptionReturn(Core& c, uint32_t excReturn);
	void CheckInterrupts(Core& c);

	bool HandleHle(Core& c, uint32_t pc);
	HleResult RunHook(Core& c, int hook);
	void HleReturn(Core& c, uint32_t r0);
	void HleReturn64(Core& c, uint64_t v);
	uint64_t TimeUs(Core& c) { return c.Cycles / (CpuFreq / 1000000); }
	std::string ReadCString(uint32_t addr, size_t max = 256);
	std::string FormatPrintf(Core& c, uint32_t fmtAddr, int firstArg);
	void HleBootRomFunc(Core& c, uint32_t index);
	void HleBrrEncode(Core& c);
};
