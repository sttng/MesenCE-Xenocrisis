#include "pch.h"
#include "SNES/Coprocessors/XenoCrisis/XenoCrisis.h"
#include "SNES/SnesConsole.h"
#include "SNES/SnesMemoryManager.h"
#include "SNES/MemoryMappings.h"
#include "Shared/Emulator.h"
#include "Shared/BatteryManager.h"
#include "Shared/MessageManager.h"
#include "Utilities/VirtualFile.h"
#include "Utilities/FolderUtilities.h"
#include "Utilities/Serializer.h"

bool XenoCrisis::IsXenoCrisis(uint8_t romType, const uint8_t makerCode[2], const uint8_t gameCode[4])
{
	//Header: chipset $63 (coprocessor nibble 6 is not assigned by Nintendo), maker "BM", game code "XCRI"
	return romType == 0x63 && makerCode[0] == 'B' && makerCode[1] == 'M' && memcmp(gameCode, "XCRI", 4) == 0;
}

XenoCrisis::XenoCrisis(SnesConsole* console, VirtualFile& romFile)
{
	_console = console;
	_emu = console->GetEmulator();
	_memoryManager = console->GetMemoryManager();

	MemoryMappings* mappings = _memoryManager->GetMemoryMappings();
	mappings->RegisterHandler(0x00, 0x3F, 0x3000, 0x3FFF, this);
	mappings->RegisterHandler(0x80, 0xBF, 0x3000, 0x3FFF, this);

	_rp.Log = [](const string& msg) { MessageManager::Log(msg); };

	string romFolder = romFile.GetFolderPath();
	string romName = FolderUtilities::GetFilename(romFile.GetFileName(), false);
	vector<string> candidates = {
		FolderUtilities::CombinePath(romFolder, romName + ".rp2040"),
		FolderUtilities::CombinePath(romFolder, "xenocrisis_rp2040.bin"),
		FolderUtilities::CombinePath(FolderUtilities::GetFirmwareFolder(), "xenocrisis_rp2040.bin"),
	};

	for(string& path : candidates) {
		VirtualFile file(path);
		if(!file.IsValid() || file.GetSize() == 0) {
			continue;
		}
		vector<uint8_t> image;
		file.ReadFile(image);
		string error;
		if(_rp.LoadFlash(image.data(), image.size(), error)) {
			MessageManager::Log("[Xeno Crisis] RP2040 flash image loaded: " + path);
			_loaded = true;
			break;
		} else {
			MessageManager::Log("[Xeno Crisis] " + path + ": " + error);
		}
	}

	if(!_loaded) {
		MessageManager::DisplayMessage("Error", "Xeno Crisis: RP2040 flash image not found (" + romName + ".rp2040 or xenocrisis_rp2040.bin)");
	}

	_masterClockRate = _console->GetMasterClockRate();
	_rp.PowerOn();
}

void XenoCrisis::Reset()
{
	//The cartridge's /RESET line also resets the RP2040
	std::vector<uint8_t> saveArea(&_rp.Flash[Rp2040::SaveOffset], &_rp.Flash[Rp2040::SaveOffset] + Rp2040::SaveSize);
	_rp.PowerOn();
	memcpy(&_rp.Flash[Rp2040::SaveOffset], saveArea.data(), Rp2040::SaveSize);
	_masterClockBase = _memoryManager->GetMasterClock();
	_rpCycleBase = 0;
	_faultReported = false;
}

void XenoCrisis::Sync()
{
	if(!_loaded) {
		return;
	}
	uint64_t master = _memoryManager->GetMasterClock();
	if(master < _masterClockBase) {
		_masterClockBase = master;
	}
	//Exact integer conversion from SNES master clocks to RP2040 cycles (no drift, no 64-bit overflow)
	uint64_t delta = master - _masterClockBase;
	uint64_t rate = _masterClockRate;
	uint64_t target = _rpCycleBase + (delta / rate) * Rp2040::CpuFreq + (delta % rate) * Rp2040::CpuFreq / rate;
	_rp.RunUntil(target);

	if(_rp.Faulted && !_faultReported) {
		_faultReported = true;
		MessageManager::DisplayMessage("Error", "Xeno Crisis RP2040: " + _rp.FaultMessage);
	}
}

void XenoCrisis::Run()
{
	Sync();
}

void XenoCrisis::ProcessEndOfFrame()
{
	Sync();
}

uint8_t XenoCrisis::Read(uint32_t addr)
{
	Sync();
	_nextReadAddr = (uint16_t)(addr + 1);
	return _rp.SnesRead();
}

void XenoCrisis::Write(uint32_t addr, uint8_t value)
{
	Sync();
	_rp.SnesWrite(value);
}

uint8_t XenoCrisis::Peek(uint32_t addr)
{
	//Reads have side effects (they pop the stream), so peeking shows queued bytes without consuming them.
	//While the SNES executes streamed code (JSL $00:3000), the byte at the next sequential address is the next
	//queued byte, so the debugger's disassembly at PC shows the upcoming instructions.
	int32_t offset = (int32_t)(uint16_t)addr - (int32_t)_nextReadAddr;
	if(offset >= 0 && offset < (int32_t)_rp.TxFifo.size()) {
		return _rp.TxFifo[(size_t)offset];
	}
	return _rp.TxFifo.empty() ? 0 : _rp.TxFifo.front();
}

void XenoCrisis::PeekBlock(uint32_t addr, uint8_t* output)
{
	uint32_t base = addr & ~0xFFFu;
	for(uint32_t i = 0; i < 0x1000; i++) {
		output[i] = Peek(base + i);
	}
}

AddressInfo XenoCrisis::GetAbsoluteAddress(uint32_t address)
{
	return { -1, MemoryType::None };
}

void XenoCrisis::LoadBattery()
{
	//The firmware keeps its saves in the last 32KB of the RP2040 flash
	vector<uint8_t> save = _emu->GetBatteryManager()->LoadBattery(".srm");
	if(save.size() == Rp2040::SaveSize) {
		memcpy(&_rp.Flash[Rp2040::SaveOffset], save.data(), Rp2040::SaveSize);
	}
}

void XenoCrisis::SaveBattery()
{
	_emu->GetBatteryManager()->SaveBattery(".srm", &_rp.Flash[Rp2040::SaveOffset], Rp2040::SaveSize);
	_rp.SaveDirty = false;
}

void XenoCrisis::Serialize(Serializer& s)
{
	vector<uint8_t> rpState;
	if(s.IsSaving()) {
		_rp.SaveState(rpState);
	}
	SVVector(rpState);
	SV(_masterClockBase);
	SV(_rpCycleBase);
	if(!s.IsSaving()) {
		_rp.LoadState(rpState);
		_faultReported = false;
	}
}
