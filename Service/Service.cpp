/*
 * Service control for the provider driver.
 *
 * The provider is registered the same way a normal kernel service is: a key
 * under HKLM\SYSTEM\CurrentControlSet\Services with an ImagePath, loaded
 * through NtLoadDriver. A key created by this run is removed on failure and by
 * StopAndRemove; a pre-existing key is restored to its original values instead
 * of being deleted.
 */

#include "Service.hpp"
#include <Windows.h>
#include <string>
#include <iostream>
#include <vector>

#include "../Utilities/Support/Console.hpp"
#include "../App/NT.hpp"

namespace
{
	/*
	 * Original values of a service key that already existed before we loaded.
	 *
	 * RegisterAndStart saves them on success; StopAndRemove restores them instead
	 * of deleting the key. A failure path inside RegisterAndStart already did its
	 * own restore before returning, so this state only describes a load that
	 * succeeded and therefore has a matching unload.
	 */

	struct SavedServiceKey {
		std::wstring name;
		bool existed = false;
		bool have_image = false;
		DWORD image_type = REG_SZ;
		std::wstring image_path;
		bool have_type = false;
		DWORD type_data = 0;
		DWORD type_len = 0;
	};

	SavedServiceKey g_savedServiceKey{};

	void RestoreSavedValues(HKEY key, const SavedServiceKey& saved) {
		if (saved.have_image) {
			RegSetKeyValueW(key, NULL, L"ImagePath", saved.image_type,
				saved.image_path.c_str(),
				static_cast<DWORD>((saved.image_path.size() + 1) * sizeof(wchar_t)));
		}
		else {
			RegDeleteKeyValueW(key, NULL, L"ImagePath");
		}

		if (saved.have_type) {
			RegSetKeyValueW(key, NULL, L"Type", REG_DWORD,
				&saved.type_data, saved.type_len);
		}
		else {
			RegDeleteKeyValueW(key, NULL, L"Type");
		}
	}
}

//The kernel expects \??\<full path> as an NT object path.

NTSTATUS Service::RegisterAndStart(const std::wstring& driver_path, const std::wstring& serviceName) {
	const static DWORD ServiceTypeKernel = SERVICE_KERNEL_DRIVER;
	const std::wstring servicesPath = L"SYSTEM\\CurrentControlSet\\Services\\" + serviceName;
	const std::wstring nPath = L"\\??\\" + driver_path;

	/* Detect pre-existence by opening the key BEFORE creating it. Looking only
	 * for ImagePath/Type/Start misclassified an existing key that held other
	 * values (or none), so a failed load deleted somebody else's service key. */

	HKEY existing_key = nullptr;
	const bool key_existed = RegOpenKeyExW(HKEY_LOCAL_MACHINE, servicesPath.c_str(),
		0, KEY_READ, &existing_key) == ERROR_SUCCESS;
	if (existing_key)
		RegCloseKey(existing_key);

	HKEY dservice;
	LSTATUS status = RegCreateKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str(), &dservice);
	if (status != ERROR_SUCCESS) {
		Log("[-] Can't create service key" << std::endl);
		return STATUS_REGISTRY_IO_FAILED;
	}

	/*
	 * Every failure path below deletes the whole key, which is right for a key
	 * this run created and wrong for one it found: RegCreateKeyW opens an
	 * existing key rather than failing, so a vendor-installed service under a
	 * colliding name was silently removed by a run that had failed before it
	 * ever loaded anything. The cleanup deletes only what was created here, and
	 * otherwise leaves the pre-existing key alone.
	 */

	DWORD orig_type_len = 0;
	DWORD orig_type_data = 0;
	DWORD orig_image_type = REG_SZ; // type of a pre-existing ImagePath, preserved on restore
	std::wstring orig_image_path;
	bool have_orig_image = false;
	bool have_orig_type = false;

	{
		DWORD sz = 0;
		DWORD image_type = REG_SZ;
		if (RegQueryValueExW(dservice, L"ImagePath", nullptr, &image_type, nullptr, &sz) == ERROR_SUCCESS && sz > 0)
		{
			std::vector<wchar_t> buf(sz / sizeof(wchar_t) + 1);
			DWORD got = sz;
			if (RegQueryValueExW(dservice, L"ImagePath", nullptr, &image_type,
					reinterpret_cast<LPBYTE>(buf.data()), &got) == ERROR_SUCCESS)
			{
				orig_image_path.assign(buf.data());
				orig_image_type = image_type;
				have_orig_image = true;
			}
		}

		DWORD got = sizeof(orig_type_data);
		if (RegQueryValueExW(dservice, L"Type", nullptr, nullptr,
				reinterpret_cast<LPBYTE>(&orig_type_data), &got) == ERROR_SUCCESS)
		{
			orig_type_len = got;
			have_orig_type = true;
		}
	}

	const auto restore_or_delete_service_key = [&]() {
		if (key_existed)
		{
			HKEY restore_key;
			LSTATUS rs = RegOpenKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str(), &restore_key);
			if (rs == ERROR_SUCCESS)
			{
				if (have_orig_image)
				{
					RegSetKeyValueW(restore_key, NULL, L"ImagePath", orig_image_type,
						orig_image_path.c_str(),
						static_cast<DWORD>((orig_image_path.size() + 1) * sizeof(wchar_t)));
				}
				else
				{
					RegDeleteKeyValueW(restore_key, NULL, L"ImagePath");
				}

				if (have_orig_type)
				{
					RegSetKeyValueW(restore_key, NULL, L"Type", REG_DWORD,
						&orig_type_data, orig_type_len);
				}
				else
				{
					RegDeleteKeyValueW(restore_key, NULL, L"Type");
				}
				RegCloseKey(restore_key);
				Log(L"[*] A service key of this name already existed; its original values were restored" << std::endl);
			}
			return;
		}

		RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
	};

	//REG_EXPAND_SZ includes the terminating null in the stored length.

	status = RegSetKeyValueW(dservice, NULL, L"ImagePath", REG_EXPAND_SZ, nPath.c_str(), (DWORD)(nPath.size() + 1) * sizeof(wchar_t));
	if (status != ERROR_SUCCESS) {
		RegCloseKey(dservice);
		restore_or_delete_service_key();
		Log("[-] Can't create 'ImagePath' registry value" << std::endl);
		return STATUS_REGISTRY_IO_FAILED;
	}

	status = RegSetKeyValueW(dservice, NULL, L"Type", REG_DWORD, &ServiceTypeKernel, sizeof(DWORD));
	if (status != ERROR_SUCCESS) {
		RegCloseKey(dservice);
		restore_or_delete_service_key();
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
		restore_or_delete_service_key();
		Log("[-] Fatal error: failed to acquire SE_LOAD_DRIVER_PRIVILEGE. Make sure you are running as administrator." << std::endl);
		return ntStatus;
	}

	std::wstring wdriver_reg_path = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + serviceName;
	UNICODE_STRING serviceStr;
	RtlInitUnicodeString(&serviceStr, wdriver_reg_path.c_str());

	ntStatus = Nt::NtLoadDriver(&serviceStr);

	Log((NT_SUCCESS(ntStatus) ? L"[+]" : L"[-]") << L" NtLoadDriver Status "
		<< Val(Hex(ntStatus)) << std::endl);

	if (ntStatus == STATUS_IMAGE_CERT_REVOKED) {
		Log("[-] Your vulnerable driver blocklist is enabled and has blocked the provider from loading, you must disable it" << std::endl);
		Log("[-] Registry path to disable vulnerable driver list: HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config" << std::endl);
		Log("[-] Set 'VulnerableDriverBlocklistEnable' as dword to 0" << std::endl);
	}
	else if (ntStatus == STATUS_ACCESS_DENIED || ntStatus == STATUS_INSUFFICIENT_RESOURCES) {
		Log(L"[-] Access Denied or Insufficient Resources (" << Val(Hex(ntStatus)) << L"), Probably some anticheat or antivirus running blocking the load of vulnerable driver" << std::endl);
	}

	if (!NT_SUCCESS(ntStatus)) {

		//A pre-existing key is restored to its original values; a key this run
		//created is deleted. The helper reopens its own key handle because
		//RegCloseKey(dservice) already ran, so the original handle is closed
		//by the time NtLoadDriver has returned.

		restore_or_delete_service_key();
	}

	/*
	 * Put the privilege back the way it was found, on BOTH outcomes.
	 *
	 * RtlAdjustPrivilege was asked to enable it and reported what it was
	 * before doing so. Nothing in the map path after the load needs it.
	 * StopAndRemove does need it (NtUnloadDriver requires the same
	 * SeLoadDriverPrivilege), so it re-enables it itself before it calls
	 * NtUnloadDriver, which is why restoring it here does not block the
	 * later unload. A failed load must not leave the process holding a
	 * privilege it only acquired for that one call: the earlier failure path
	 * restored the registry key but skipped this, so the token stayed raised.
	 */

	if (!SeLoadDriverWasEnabled) {
		BOOLEAN restored = FALSE;
		Nt::RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, FALSE, FALSE, &restored);
	}

	//Only a successful load reaches here. Remember whether the key was ours or
	//pre-existing so StopAndRemove can restore instead of delete it.
	if (NT_SUCCESS(ntStatus)) {
		g_savedServiceKey.name = serviceName;
		g_savedServiceKey.existed = key_existed;
		g_savedServiceKey.have_image = have_orig_image;
		g_savedServiceKey.image_type = orig_image_type;
		g_savedServiceKey.image_path = orig_image_path;
		g_savedServiceKey.have_type = have_orig_type;
		g_savedServiceKey.type_data = orig_type_data;
		g_savedServiceKey.type_len = orig_type_len;
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
			g_savedServiceKey = SavedServiceKey{};
			return STATUS_SUCCESS; //already removed
		}
		return STATUS_REGISTRY_IO_FAILED;
	}
	RegCloseKey(driver_service);

	/* A key that already existed before RegisterAndStart must be restored, not
	 * deleted: deleting it removes somebody else's service registration. Keys
	 * this run created still get the tree delete below. */

	const auto restore_or_delete = [&]() -> LSTATUS {
		if (g_savedServiceKey.name == serviceName && g_savedServiceKey.existed) {
			HKEY key = nullptr;
			const LSTATUS opened = RegOpenKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str(), &key);
			if (opened != ERROR_SUCCESS)
				return opened;
			RestoreSavedValues(key, g_savedServiceKey);
			RegCloseKey(key);
			Log(L"[*] Pre-existing service key restored on unload" << std::endl);
			return ERROR_SUCCESS;
		}
		return RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
	};

	/*
	 * NtUnloadDriver needs SeLoadDriverPrivilege enabled, just like NtLoadDriver.
	 *
	 * RegisterAndStart enables that privilege for the load and then restores it
	 * to its pre-load state afterwards, so by the time StopAndRemove runs it is
	 * disabled again. Calling NtUnloadDriver without it fails with
	 * STATUS_PRIVILEGE_NOT_HELD (0xc0000061): the driver stays loaded, its
	 * service key is deleted out from under it, and the wipe that follows can no
	 * longer free the file because the I/O manager still holds it open - which is
	 * exactly the "still resident, file can't be removed" state StopAndRemove's
	 * caller has to warn about. Re-enable the privilege here for the unload, then
	 * restore the prior state so the teardown does not leave it raised for the
	 * rest of the process, matching RegisterAndStart's least-privilege handling.
	 */

	const ULONG kSeLoadDriverPrivilege = 10UL;
	BOOLEAN SeLoadDriverWasEnabled = FALSE;
	const NTSTATUS priv_status = Nt::RtlAdjustPrivilege(kSeLoadDriverPrivilege, TRUE, FALSE, &SeLoadDriverWasEnabled);
	if (!NT_SUCCESS(priv_status)) {
		Log(L"[-] Failed to enable SeLoadDriverPrivilege for NtUnloadDriver (" << Val(Hex(priv_status)) << L")" << std::endl);
	}

	NTSTATUS st = Nt::NtUnloadDriver(&serviceStr);
	Log((NT_SUCCESS(st) ? L"[+]" : L"[-]") << L" NtUnloadDriver Status: "
		<< Val(Hex(st)) << std::endl);

	/*
	 * Restore the privilege to its prior state before the failure path below
	 * runs: the registry key is still deleted whether or not the unload
	 * succeeded, and nothing should be left raised either way.
	 */

	if (NT_SUCCESS(priv_status) && !SeLoadDriverWasEnabled) {
		BOOLEAN restored = FALSE;
		Nt::RtlAdjustPrivilege(kSeLoadDriverPrivilege, FALSE, FALSE, &restored);
	}

	if (!NT_SUCCESS(st)) {
		Log("[-] Driver Unload Failed!!" << std::endl);
		(void)restore_or_delete();
		g_savedServiceKey = SavedServiceKey{};
		return st; //lets consider unload fail as error because can cause problems with anti cheats later
	}

	status = restore_or_delete();
	g_savedServiceKey = SavedServiceKey{};
	if (status != ERROR_SUCCESS) {
		return STATUS_REGISTRY_IO_FAILED;
	}
	return st;
}
