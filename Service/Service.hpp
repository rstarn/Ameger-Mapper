#pragma once
#include <string>
#include "Nt.hpp"

namespace Service
{
	NTSTATUS RegisterAndStart(const std::wstring& driver_path, const std::wstring& serviceName);
	NTSTATUS StopAndRemove(const std::wstring& serviceName);
};