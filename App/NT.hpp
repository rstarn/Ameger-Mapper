#pragma once

/*
 * Kernel types.
 *
 * Only the *shapes* of these structures are compiled in. Every address and
 * every field offset used to walk kernel memory comes from the PDB of the
 * running build and is resolved at runtime into Offsets.ini, because these
 * layouts change between Windows releases and there is no supported way to
 * learn them from user mode.
 */

#include <Windows.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

#pragma warning(push)
#pragma warning(disable: 4005) //macro redefinition
#include <ntstatus.h>
#pragma warning(pop)

namespace Nt
{
	//SYSTEM_INFORMATION_CLASS values used here, spelled out because the enum is
	//not part of the documented SDK surface.
	constexpr auto SystemModuleInformation = 11;
	constexpr auto SystemExtendedHandleInformation = 64;

	//Resolved through the export table rather than declared and linked, but
	//ntdll exports them, so a direct declaration is enough.
	extern "C" NTSTATUS NtLoadDriver(PUNICODE_STRING DriverServiceName);
	extern "C" NTSTATUS NtUnloadDriver(PUNICODE_STRING DriverServiceName);
	extern "C" NTSTATUS RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN Client, BOOLEAN* WasEnabled);

	/*
	 * SystemModuleInformation result, used to locate loaded kernel modules.
	 * FullPathName holds the full path and OffsetToFileName is the byte offset
	 * of the base name inside it, so the file name is
	 * FullPathName + OffsetToFileName.
	 */
	typedef struct _RTL_PROCESS_MODULE_INFORMATION
	{
		HANDLE Section;
		PVOID MappedBase;
		PVOID ImageBase;
		ULONG ImageSize;
		ULONG Flags;
		USHORT LoadOrderIndex;
		USHORT InitOrderIndex;
		USHORT LoadCount;
		USHORT OffsetToFileName;
		//Must be 256: this is the size the kernel uses, and it fixes the array
		//stride at sizeof(_RTL_PROCESS_MODULE_INFORMATION) = 296 on x64. A
		//different value (e.g. 260) pads the struct to 304 and every entry after
		//the first is read misaligned, so module lookups beyond the first module
		//walk into garbage pointers.
		UCHAR FullPathName[256];
	} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

	//Header of the module list returned by SystemModuleInformation, followed by
	//NumberOfModules entries. Declared as a flexible array member.
	typedef struct _RTL_PROCESS_MODULES
	{
		ULONG NumberOfModules;
		RTL_PROCESS_MODULE_INFORMATION Modules[1];
	} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

	/*
	 * SystemExtendedHandleInformation result.
	 *
	 * This is how the mapper reaches the FILE_OBJECT behind its own device
	 * handle: the handle table is the only handle on the system that points at
	 * an object whose location is guaranteed to be the one we opened, so it
	 * removes the need to guess any kernel address to find the device object.
	 */
	typedef struct _SYSTEM_HANDLE
	{
		PVOID Object;
		HANDLE UniqueProcessId;
		HANDLE HandleValue;
		ULONG GrantedAccess;
		USHORT CreatorBackTraceIndex;
		USHORT ObjectTypeIndex;
		ULONG HandleAttributes;
		ULONG Reserved;
	} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

	typedef struct _SYSTEM_HANDLE_INFORMATION_EX
	{
		ULONG_PTR HandleCount;
		ULONG_PTR Reserved;
		SYSTEM_HANDLE Handles[1];
	} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

	//POOL_TYPE as the kernel defines it. Only NonPagedPool is used: the mapped
	//image must be executable and must not be paged out.
	//The _Nx values are separate pool types on modern Windows, not aliases.
	typedef enum class _POOL_TYPE {
		NonPagedPool,
		NonPagedPoolExecute = NonPagedPool,
		PagedPool,
		NonPagedPoolMustSucceed = NonPagedPool + 2,
		DontUseThisType,
		NonPagedPoolCacheAligned = NonPagedPool + 4,
		PagedPoolCacheAligned,
		NonPagedPoolCacheAlignedMustS = NonPagedPool + 6,
		MaxPoolType,
		NonPagedPoolNx = 512,
		NonPagedPoolNxCacheAligned = NonPagedPoolNx + 4,
		NonPagedPoolSessionNx = NonPagedPoolNx + 32,
	} POOL_TYPE;

	/*
	 * ci.dll code integrity hash bucket entry, the list of driver images the
	 * kernel has recorded a hash for.
	 *
	 * This type is NOT a public UDT, so its layout cannot be taken from the
	 * PDB. DriverName lives at the compiled default offset and every use is
	 * confirmed by matching the expected string content first; see
	 * FindUnicodeStringFieldByContent in Driver.cpp.
	 */
	typedef struct _HashBucketEntry
	{
		struct _HashBucketEntry* Next;
		UNICODE_STRING DriverName;
		ULONG CertHash[5];
	} HashBucketEntry, * PHashBucketEntry;

	//Self balancing tree node, the root element of an RTL_AVL_TABLE.
	typedef struct _RTL_BALANCED_LINKS {
		struct _RTL_BALANCED_LINKS* Parent;
		struct _RTL_BALANCED_LINKS* LeftChild;
		struct _RTL_BALANCED_LINKS* RightChild;
		CHAR Balance;
		UCHAR Reserved[3];
	} RTL_BALANCED_LINKS;

	/*
	 * The AVL table behind PiDDBCacheTable.
	 *
	 * DeleteCount is read from the PDB (DriverOffsets::AvlTable_DeleteCount)
	 * and decremented after an entry is deleted, because
	 * RtlDeleteElementGenericTableAvl only updates the count when it can, and
	 * the kernel uses it as a signal that the table was tampered with.
	 */
	typedef struct _RTL_AVL_TABLE {
		RTL_BALANCED_LINKS BalancedRoot;
		PVOID OrderedPointer;
		ULONG WhichOrderedElement;
		ULONG NumberGenericTableElements;
		ULONG DepthOfTree;
		PVOID RestartKey;
		ULONG DeleteCount;
		PVOID CompareRoutine;
		PVOID AllocateRoutine;
		PVOID FreeRoutine;
		PVOID TableContext;
	} RTL_AVL_TABLE;
	typedef RTL_AVL_TABLE* PRTL_AVL_TABLE;

	/*
	 * One entry of PiDDBCacheTable: the record the kernel keeps of a loaded
	 * driver image.
	 *
	 * Used as the lookup key for RtlLookupElementGenericTableAvl, so DriverName
	 * and TimeDateStamp must sit at the offsets the table's own compare
	 * routine reads them from - otherwise the comparison silently fails.
	 * RtlLookupElementGenericTableAvl is not exported on current Windows, so
	 * both values come from the PDB and the resulting entry is then validated
	 * by content before anything is written.
	 */
	typedef struct _PiDDBCacheEntry
	{
		LIST_ENTRY		List;
		UNICODE_STRING	DriverName;
		ULONG			TimeDateStamp;
		NTSTATUS		LoadStatus;
		char			_0x0028[16]; // shim engine data, or uninitialized memory for custom drivers
	} PiDDBCacheEntry;
}