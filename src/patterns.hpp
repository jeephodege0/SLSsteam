#pragma once

#include "libmem/libmem.h"

// The comments may not be accurate, TODO fix comments
namespace Patterns
{
	//string xref
	constexpr lm_string_t CheckAppOwnership = "E8 ? ? ? ? FF 75 ? 8D 8E ? ? ? ? E8 ? ? ? ? 8B F0 89 75";

	//string xref
	constexpr lm_string_t FamilyGroupRunningApp = "E8 ? ? ? ? 83 C4 08 84 C0 0F 84 ? ? ? ? 33 F6 EB ? ? ? ? ? ? ? ? 8B C6";

	//string xref
	constexpr lm_string_t StopPlayingBorrowedApp = "8B 40 ? 52 8B 44";

	//s-xref - breakpoint at call of vfunc - into for that function - xref
	constexpr lm_string_t GetSubscribedApps = "E8 ? ? ? ? 84 C0 75 ? 38 45 ? 74 ? 83 7E ? 07";

	//Relative TODO
	constexpr lm_string_t IsUserSubscribedAppInTicket = "E8 ? ? ? ? 8D 8D ? ? ? ? 8B F0 E8 ? ? ? ? 8B 4D ? 83 C1 FC";

	//Relative
	constexpr lm_string_t IsSubscribedApp = "E8 ? ? ? ? 84 C0 74 ? 8B 0D ? ? ? ? 6A 00 57";
	
	//End of function TODO
	// constexpr lm_string_t RequiresLegacyCDKey = "C2 08 00 68 ? ? ? ? 68 6D 0B 00 00";

	//s-xref - breakpoint at call of vfunc - into for that function
	constexpr lm_string_t GetSteamId = "E8 ? ? ? ? 8B C8 85 C9 74 ? C6 41 ? 01 C7 41 ? 00 00 00 00 C7 41 ? 00 00 00 00 A1 ? ? ? ? 89 41 ? A1 ? ? ? ? 89 41 ? A1 ? ? ? ? 89 41 ? A1 ? ? ? ? 89 41 ? A1 ? ? ? ? 89 41 ? C7 41 ? FF FF FF FF 66 C7 41 ? 00 00 8B 35 ? ? ? ? 8D 8E ? ? ? ? E8";


	//PipeLoops - string xref - biggest one

	constexpr lm_string_t IClientAppManager_PipeLoop = "68 ? ? ? ? FF 10 6A 04 8D 45 ? C7 45 ? 00 00 00 00 50 53 E8 ? ? ? ? 8B 45 ? 83 C4 0C 05 01 00 5B 02";

	constexpr lm_string_t IClientApps_PipeLoop = "68 ? ? ? ? FF 75 ? 57 E8 ? ? ? ? 83 C4 20 5F 5E 5B 8B E5 5D C3 FF 15 ? ? ? ? 68 ? ? ? ? 68 ? ? ? ? 8B F8 89 55 ? E8 ? ? ? ? 8B 4D ? 83 C4 08 85 C9 74 ? 8B 01 68 ? ? ? ? 68 ? ? ? ? FF 10 6A 04 8D 45 ? C7 45 ? 00 00 00 00";

	constexpr lm_string_t IClientRemoteStorage_PipeLoop = "? ? ? ? 56 57 6A 04 50 53 ? ? ? ? ? ? ? ? ? ? ? 3D A2 AB";

	//should be where the string GetSubscribedApps is cross referenced (xrefed) - biggest one
	constexpr lm_string_t IClientUser_PipeLoop = "? ? ? ? ? ? ? ? ? ? ? ? ? ? ? 56 57 8B 7B 0C ? ? ? 6A";

	//It should be called directly after the IClientUser and GetSubscribedApps strings get pushed onto the stack
	constexpr lm_string_t LogSteamPipeCall = "E8 ? ? ? ? 8B 4D ? 83 C4 08 85 C9 74 ? 8B 01 68 ? ? ? ? 68 ? ? ? ? FF 10 6A 04 8D 45 ? 50 57 E8 ? ? ? ? FF 75 ? E8 ? ? ? ? 6A 04 8D 45 ? C7 45 ? 00 00 00 00 50 57 E8 ? ? ? ? 8B 45 ? 83 C4 1C 05 4A 30 13 01";

}


