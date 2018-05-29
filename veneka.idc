#include <idc.idc>

static main() {

	auto addr = BeginEA();
	auto func = LocByName("kernel32_GetProcAddress");
	auto func1 = LocByName("kernel32_LoadLibraryA");
	if (func)
		Message("found GetProcName\n");
	if (func1)
		Message("found LoadLibraryA\n");
	if (AddBpt(func))
		Message("BP set for GetProcName\n");
	if (AddBpt(func1))
		Message("BP set for LoadLibraryA\n");
	SetBptCnd(func, "bpt_GetProcAddress()");
	SetBptCnd(func1, "bpt_LoadLibraryA()");
	RunTo(addr);
}
static bpt_GetProcAddress() {
	auto return_address = Dword(ESP);
	auto hModule = Dword(ESP + 4);
	auto lpProcName = Dword(ESP + 8);
	lpProcName = GetString( lpProcName, -1, GetStringType(lpProcName));
	Message("GetProcAddress: Attempting to retrieve the address of imported function %s", lpProcName);
	AddBpt(return_address);
	SetBptCnd(return_address, "bpt_GPAReturn()");
	return 0;
}
static bpt_GPAReturn() {
	if (EAX == 0)
		Message(".. FAILED\n");
	else
		Message(".. SUCCESSFUL\n");
	return 0;
}
static bpt_LoadLibraryA() {
	auto return_address = Dword(ESP);
	auto lpFileName = Dword(ESP + 4);
	lpFileName = GetString( lpFileName, -1, GetStringType(lpFileName));
	Message("LoadLibraryA: Attempting to load module %s", lpFileName);
	AddBpt(return_address);
	SetBptCnd(return_address, "bpt_LLReturn()");
	return 0;
}
static bpt_LLReturn() {
	if (EAX == 0)
		Message(".. FAILED\n");
	else
		Message(".. SUCCESSFUL\n");
	return 0;
}