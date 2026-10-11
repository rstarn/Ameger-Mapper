/*
 * Service control for the provider driver.
 *
 * The provider is registered the same way a normal kernel service is: a key
 * under HKLM\SYSTEM\CurrentControlSet\Services with an ImagePath, loaded
 * through NtLoadDriver. The key is removed again on every failure path and by
 * StopAndRemove, so a failed run does not leave a service entry behind.
 */

#include "Service.hpp"
#include <Windows.h>
#include <string>
#include <iostream>

#include "../Utilities/Console.hpp"
#include "../App/NT.hpp"

//The kernel expects \??\<full path> as an NT object path.
NTSTATUS Service::RegisterAndStart(const std::wstring& driver_path, const std::wstring& serviceName) {
	const static DWORD ServiceTypeKernel = SERVICE_KERNEL_DRIVER;
	const std::wstring servicesPath = L"SYSTEM\\CurrentControlSet\\Services\\" + serviceName;
	const std::wstring nPath = L"\\??\\" + driver_path;

	HKEY dservice;
	LSTATUS status = RegCreateKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str(), &dservice); //Returns Ok if already exists
	if (status != ERROR_SUCCESS) {
		Log("[-] Can't create service key" << std::endl);
		return STATUS_REGISTRY_IO_FAILED;
	}

	//REG_EXPAND_SZ includes the terminating null in the stored length.
	status = RegSetKeyValueW(dservice, NULL, L"ImagePath", REG_EXPAND_SZ, nPath.c_str(), (DWORD)(nPath.size() + 1) * sizeof(wchar_t));
	if (status != ERROR_SUCCESS) {
		RegCloseKey(dservice);
		RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
		Log("[-] Can't create 'ImagePath' registry value" << std::endl);
		return STATUS_REGISTRY_IO_FAILED;
	}

	status = RegSetKeyValueW(dservice, NULL, L"Type", REG_DWORD, &ServiceTypeKernel, sizeof(DWORD));
	if (status != ERROR_SUCCESS) {
		RegCloseKey(dservice);
		RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
		Log("[-] Can't create 'Type' registry value" << std::endl);
		return STATUS_REGISTRY_IO_FAILED;
	}

	RegCloseKey(dservice);

	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL) {
		RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
		return STATUS_UNSUCCESSFUL;
	}

	ULONG SE_LOAD_DRIVER_PRIVILEGE = 10UL;
	BOOLEAN SeLoadDriverWasEnabled;
	//NtLoadDriver needs this privilege, which a normal administrator token has
	//but does not have enabled by default.
	NTSTATUS ntStatus = Nt::RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &SeLoadDriverWasEnabled);
	if (!NT_SUCCESS(ntStatus)) {
		RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
		Log("[-] Fatal error: failed to acquire SE_LOAD_DRIVER_PRIVILEGE. Make sure you are running as administrator." << std::endl);
		return ntStatus;
	}

	std::wstring wdriver_reg_path = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + serviceName;
	UNICODE_STRING serviceStr;
	RtlInitUnicodeString(&serviceStr, wdriver_reg_path.c_str());

	ntStatus = Nt::NtLoadDriver(&serviceStr);

	Log(L"[+] NtLoadDriver Status " << Val(Hex(ntStatus)) << std::endl);

	if (ntStatus == STATUS_IMAGE_CERT_REVOKED) {
		Log("[-] Your vulnerable driver blocklist is enabled and has blocked the provider from loading, you must disable it" << std::endl);
		Log("[-] Registry path to disable vulnerable driver list: HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config" << std::endl);
		Log("[-] Set 'VulnerableDriverBlocklistEnable' as dword to 0" << std::endl);
	}
	else if (ntStatus == STATUS_ACCESS_DENIED || ntStatus == STATUS_INSUFFICIENT_RESOURCES) {
		Log(L"[-] Access Denied or Insufficient Resources (" << Val(Hex(ntStatus)) << L"), Probably some anticheat or antivirus running blocking the load of vulnerable driver" << std::endl);
	}

	if (!NT_SUCCESS(ntStatus)) {
		//Remove the service
		status = RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
		if (status != ERROR_SUCCESS) {
			Log("[-] Can't delete service registry key after NtLoadDriver failure" << std::endl);
		}
	}

	return ntStatus;
}

NTSTATUS Service::StopAndRemove(const std::wstring& serviceName) {
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL)
		return STATUS_UNSUCCESSFUL;

	std::wstring wdriver_reg_path = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + serviceName;
	UNICODE_STRING serviceStr;
	RtlInitUnicodeString(&serviceStr, wdriver_reg_path.c_str());

	HKEY driver_service;
	std::wstring servicesPath = L"SYSTEM\\CurrentControlSet\\Services\\" + serviceName;
	LSTATUS status = RegOpenKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str(), &driver_service);
	if (status != ERROR_SUCCESS) {
		if (status == ERROR_FILE_NOT_FOUND) {
			return STATUS_SUCCESS; //already removed
		}
		return STATUS_REGISTRY_IO_FAILED;
	}
	RegCloseKey(driver_service);

	NTSTATUS st = Nt::NtUnloadDriver(&serviceStr);
	Log(L"[+] NtUnloadDriver Status: " << Val(Hex(st)) << std::endl);
	if (!NT_SUCCESS(st)) {
		Log("[-] Driver Unload Failed!!" << std::endl);
		RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
		return st; //lets consider unload fail as error because can cause problems with anti cheats later
	}

	status = RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
	if (status != ERROR_SUCCESS) {
		return STATUS_REGISTRY_IO_FAILED;
	}
	return st;
}
