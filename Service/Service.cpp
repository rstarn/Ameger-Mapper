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
	LSTATUS status = RegCreateKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str(), &dservice);
	if (status != ERROR_SUCCESS) {
		Log("[-] Can't create service key" << std::endl);
		return STATUS_REGISTRY_IO_FAILED;
	}

	/*
	 * Whether this key already existed.
	 *
	 * Every failure path below deletes the whole key, which is right for a key
	 * this run created and wrong for one it found: RegCreateKeyW opens an
	 * existing key rather than failing, so a vendor-installed service under a
	 * colliding name was silently removed by a run that had failed before it
	 * ever loaded anything. The cleanup deletes only what was created here, and
	 * otherwise leaves the pre-existing key alone.
	 */
	const bool key_existed = RegQueryValueExW(dservice, L"ImagePath", nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS ||
		RegQueryValueExW(dservice, L"Type", nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS ||
		RegQueryValueExW(dservice, L"Start", nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS;

	const auto discard_service_key = [&]() {
		if (key_existed) {
			Log(L"[*] A service key of this name already existed and was left in place" << std::endl);
			return;
		}
		RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
	};

	//REG_EXPAND_SZ includes the terminating null in the stored length.
	status = RegSetKeyValueW(dservice, NULL, L"ImagePath", REG_EXPAND_SZ, nPath.c_str(), (DWORD)(nPath.size() + 1) * sizeof(wchar_t));
	if (status != ERROR_SUCCESS) {
		RegCloseKey(dservice);
		discard_service_key();
		Log("[-] Can't create 'ImagePath' registry value" << std::endl);
		return STATUS_REGISTRY_IO_FAILED;
	}

	status = RegSetKeyValueW(dservice, NULL, L"Type", REG_DWORD, &ServiceTypeKernel, sizeof(DWORD));
	if (status != ERROR_SUCCESS) {
		RegCloseKey(dservice);
		discard_service_key();
		Log("[-] Can't create 'Type' registry value" << std::endl);
		return STATUS_REGISTRY_IO_FAILED;
	}

	RegCloseKey(dservice);

	ULONG SE_LOAD_DRIVER_PRIVILEGE = 10UL;
	BOOLEAN SeLoadDriverWasEnabled = FALSE;
	//NtLoadDriver needs this privilege, which a normal administrator token has
	//but does not have enabled by default.
	NTSTATUS ntStatus = Nt::RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &SeLoadDriverWasEnabled);
	if (!NT_SUCCESS(ntStatus)) {
		discard_service_key();
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
	else {
		/*
		 * Put the privilege back the way it was found.
		 *
		 * RtlAdjustPrivilege was asked to enable it and reported what it was
		 * before doing so, and the answer was never used. The privilege stays on
		 * for the rest of the process - and StopAndRemove, which runs afterwards,
		 * is the one call that does not need it. Nothing breaks because of it
		 * here, but a process that quietly raises its own privilege and leaves
		 * it raised is not a thing to leave in place by accident.
		 */
		if (!SeLoadDriverWasEnabled) {
			BOOLEAN restored = FALSE;
			Nt::RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, FALSE, FALSE, &restored);
		}
	}

	return ntStatus;
}

NTSTATUS Service::StopAndRemove(const std::wstring& serviceName) {
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
