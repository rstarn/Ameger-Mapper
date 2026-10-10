#pragma once

#include <Windows.h>
#include <string>

namespace Service
{
	/*
	 * Register the provider as a kernel service and load it.
	 *
	 * Creates HKLM\SYSTEM\CurrentControlSet\Services\<serviceName> with an
	 * ImagePath of \??\<driver_path>, then calls NtLoadDriver.
	 *
	 * The registry key is removed again if any step fails, so a failed run
	 * leaves no service behind.
	 *
	 * Returns STATUS_IMAGE_CERT_REVOKED when the vulnerable driver blocklist is
	 * enabled, STATUS_ACCESS_DENIED when something blocked the load.
	 */
	NTSTATUS RegisterAndStart(const std::wstring& driver_path, const std::wstring& serviceName);

	/*
	 * Unload the provider and delete its service key.
	 *
	 * Returns STATUS_SUCCESS when the key was already gone, which is the normal
	 * case when the provider was reused instead of loaded by us.
	 * An unload failure is reported as an error even though the key is removed,
	 * because a still loaded driver with no service key is a state the kernel
	 * reports differently and is worth surfacing.
	 */
	NTSTATUS StopAndRemove(const std::wstring& serviceName);
}