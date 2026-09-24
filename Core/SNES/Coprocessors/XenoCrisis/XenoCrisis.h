#pragma once
#include "pch.h"
#include "SNES/Coprocessors/BaseCoprocessor.h"
#include "SNES/Coprocessors/XenoCrisis/Rp2040.h"

class SnesConsole;
class Emulator;
class SnesMemoryManager;
class VirtualFile;

// Bitmap Bureau "Xeno Crisis" cartridge: 128KB LoROM kernel + RP2040 coprocessor.
// The RP2040 runs the game and talks to the SNES through a byte stream at $00-3F/$80-BF:$3000-3FFF:
//  - reads pop the next byte the RP2040 queued (generated 65816 code, DMA payloads, commands), $00 when empty
//  - writes push a byte to the RP2040 (handshake, per-frame joypad/APU/status reports)
// The RP2040 flash image (16MB dump of the W25Q128) is loaded from:
//  <rom folder>/<rom name>.rp2040, <rom folder>/xenocrisis_rp2040.bin or <firmware folder>/xenocrisis_rp2040.bin
class XenoCrisis final : public BaseCoprocessor
{
private:
	SnesConsole* _console = nullptr;
	Emulator* _emu = nullptr;
	SnesMemoryManager* _memoryManager = nullptr;
	Rp2040 _rp;
	bool _loaded = false;
	uint32_t _masterClockRate = 21477270;
	uint64_t _masterClockBase = 0;
	uint64_t _rpCycleBase = 0;
	bool _faultReported = false;
	uint16_t _nextReadAddr = 0x3000; //debugger only: address the SNES will most likely read next

	void Sync();

public:
	XenoCrisis(SnesConsole* console, VirtualFile& romFile);

	static bool IsXenoCrisis(uint8_t romType, const uint8_t makerCode[2], const uint8_t gameCode[4]);

	bool IsLoaded() { return _loaded; }

	void Reset() override;
	void Run() override;
	void ProcessEndOfFrame() override;

	void LoadBattery() override;
	void SaveBattery() override;

	uint8_t Read(uint32_t addr) override;
	void Write(uint32_t addr, uint8_t value) override;
	uint8_t Peek(uint32_t addr) override;
	void PeekBlock(uint32_t addr, uint8_t* output) override;
	AddressInfo GetAbsoluteAddress(uint32_t address) override;

	void Serialize(Serializer& s) override;
};
