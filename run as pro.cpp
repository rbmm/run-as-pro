#include "stdafx.h"
#include "common.h"

#define ComboBox_AddStringEx(hwndCtl, sz, Data) \
	ComboBox_SetItemData(hwndCtl, ComboBox_AddString(hwndCtl, sz), Data)

#include "../inc/idcres.h"
#include "resource.h"

_NT_BEGIN
#include "../tkn/tkn.h"

BOOL g_xp;
extern const volatile UCHAR guz = 0;
OBJECT_ATTRIBUTES zoa = { sizeof zoa };

#ifdef _WIN64

#include "../wow/wow.h"

enum { i_LoadLibraryExW, i_VirtualFree };

BEGIN_DLL_FUNCS(kernel32, 0)
	FUNC(LoadLibraryExW),
	FUNC(VirtualFree),
END_DLL_FUNCS();

#endif

NTSTATUS DisplayStatus(NTSTATUS status, PCWSTR sztext, HWND hwnd = HWND_DESKTOP)
{
	WCHAR err[MAX_PATH];

	ULONG dwFlags;
	HMODULE hmod;

	if (HRESULT_FACILITY(status) == FACILITY_WIN32)
	{
		dwFlags = FORMAT_MESSAGE_IGNORE_INSERTS|FORMAT_MESSAGE_FROM_SYSTEM;
		hmod = 0;
	}
	else
	{
		dwFlags = FORMAT_MESSAGE_IGNORE_INSERTS|FORMAT_MESSAGE_FROM_HMODULE;
		static HMODULE s_ntdll;
		if (!s_ntdll)
		{
			s_ntdll = GetModuleHandleW(L"ntdll");
		}
		hmod = s_ntdll;
	}
	
	if (FormatMessage(dwFlags, hmod, status, 0, err, RTL_NUMBER_OF(err), 0))
	{
		ULONG mb;

		switch((ULONG)status >> 30) {
	case 0: mb = MB_OK;
		break;
	case 1: mb = MB_ICONINFORMATION;
		break;
	case 2: mb = MB_ICONWARNING;
		break;
	case 3: mb = MB_ICONHAND;
		break;
	default: __assume(false);
		}

		MessageBoxW(hwnd, err , sztext, mb);
	}
	
	return status;
}

#include "../inc/rtlframe.h"

// +++ xp/2003 support

struct _EF
{
	HANDLE InheritFromProcessHandle;
};

typedef RTL_FRAME<_EF> EF;

struct EEF : public EF
{
	void* operator new(size_t, void* pv)
	{
		return pv;
	}

	void operator delete(void* /*pv*/)
	{
	}
};

#define TRACE_FLAG	0x100
#define RESUME_FLAG 0x10000

enum { oLowLevel, oTrustedIntaller, oFrozen };

LONG vex(::PEXCEPTION_POINTERS ExceptionInfo)
{
	::PEXCEPTION_RECORD ExceptionRecord = ExceptionInfo->ExceptionRecord;

	if (ExceptionRecord->ExceptionCode != STATUS_SINGLE_STEP) return EXCEPTION_CONTINUE_SEARCH;

	PVOID ExceptionAddress = ExceptionRecord->ExceptionAddress;

	if ((ExceptionAddress != ZwCreateProcessEx) && (ExceptionAddress != ZwCreateProcess)) return EXCEPTION_CONTINUE_SEARCH;

	::_CONTEXT* ContextRecord = ExceptionInfo->ContextRecord;

	if (_EF* prf = EF::get())
	{

#ifdef _WIN64 
		ContextRecord->R9
#else
		((PULONG_PTR)ContextRecord->Esp)[4]
#endif
		= (ULONG_PTR)prf->InheritFromProcessHandle;
	}

	ContextRecord->ContextFlags |= CONTEXT_DEBUG_REGISTERS;
	ContextRecord->EFlags |= RESUME_FLAG;// not work on xp, work on 2003
	ContextRecord->Dr7 = 0;
	return EXCEPTION_CONTINUE_EXECUTION;
}

// --- xp/2003 support

struct AutoImpesonate
{
	BOOLEAN _bRevertToSelf;

	~AutoImpesonate()
	{
		if (_bRevertToSelf)
		{
			HANDLE hToken = 0;
			NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &hToken, sizeof(hToken));
		}
	}

	AutoImpesonate(HANDLE hToken)
	{
		_bRevertToSelf = hToken ? 
			0 <= NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &hToken, sizeof(hToken)) : FALSE;
	}
};

BEGIN_PRIVILEGES(tp_TCB_Assign_Debug_Quota_Create_Load, 6)
	LAA(SE_TCB_PRIVILEGE),
	LAA(SE_DEBUG_PRIVILEGE),
	LAA(SE_INCREASE_QUOTA_PRIVILEGE),
	LAA(SE_ASSIGNPRIMARYTOKEN_PRIVILEGE),
	LAA(SE_CREATE_TOKEN_PRIVILEGE),
	LAA(SE_LOAD_DRIVER_PRIVILEGE)
END_PRIVILEGES	

NTSTATUS GetSystemToken(PHANDLE phSysToken, PBYTE buf)
{
	NTSTATUS status;

	union {
		PBYTE pb;
		PSYSTEM_PROCESS_INFORMATION pspi;
	};

	pb = buf;
	ULONG NextEntryOffset = 0;

	do 
	{
		pb += NextEntryOffset;

		HANDLE hProcess, hToken, hNewToken;

		if (pspi->InheritedFromUniqueProcessId && pspi->UniqueProcessId && pspi->NumberOfThreads)
		{
			static SECURITY_QUALITY_OF_SERVICE sqos = {
				sizeof sqos, SecurityImpersonation, SECURITY_DYNAMIC_TRACKING, FALSE
			};

			static OBJECT_ATTRIBUTES soa = { sizeof(soa), 0, 0, 0, 0, &sqos };

			if (0 <= NtOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION, &zoa, &pspi->TH->ClientId))
			{
				status = NtOpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken);

				NtClose(hProcess);

				if (0 <= status)
				{
					status = NtDuplicateToken(hToken, TOKEN_ADJUST_PRIVILEGES|TOKEN_IMPERSONATE, 
						&soa, FALSE, TokenImpersonation, &hNewToken);

					NtClose(hToken);

					goto __v;
				}
			}

			if (0 <= ZwOpenThread(&hProcess, THREAD_DIRECT_IMPERSONATION, &zoa, &pspi->TH->ClientId))
			{
				status = ZwImpersonateThread(NtCurrentThread(), hProcess, &sqos);

				NtClose(hProcess);

				if (0 <= status)
				{
					status = NtOpenThreadTokenEx(NtCurrentThread(), TOKEN_ADJUST_PRIVILEGES|TOKEN_IMPERSONATE,
						FALSE, 0, &hNewToken);

					NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &(hToken = 0), sizeof(hToken));

					goto __v;
				}
			}
			
			continue;

__v:
			if (0 <= status)
			{
				if (STATUS_SUCCESS == NtAdjustPrivilegesToken(hNewToken, FALSE, 
					const_cast<PTOKEN_PRIVILEGES>(&tp_TCB_Assign_Debug_Quota_Create_Load), 0, 0, 0))	
				{
					*phSysToken = hNewToken;
					return STATUS_SUCCESS;
				}

				NtClose(hNewToken);
			}
		}

	} while (NextEntryOffset = pspi->NextEntryOffset);

	return STATUS_UNSUCCESSFUL;
}

HANDLE g_hDrv;

NTSTATUS MyOpenProcess(PHANDLE ProcessHandle, ULONG DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID Cid)
{
	if (g_hDrv)
	{
		IO_STATUS_BLOCK iosb;
		NTSTATUS status = ZwDeviceIoControlFile(g_hDrv, 0, 0, 0, &iosb, IOCTL_OpenProcess, &Cid->UniqueProcess, sizeof(HANDLE), 0, 0);
		*ProcessHandle = (HANDLE)iosb.Information;
		return status;
	}
	return ZwOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, Cid);
}

BOOL LoadDrv()
{
	STATIC_UNICODE_STRING(tkn, "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\{FC81D8A3-6002-44bf-931A-352B95C4522F}");
	NTSTATUS status = ZwLoadDriver(const_cast<PUNICODE_STRING>(&tkn));

	if (0 > status && status != STATUS_IMAGE_ALREADY_LOADED)
	{
		return FALSE;
	}

	IO_STATUS_BLOCK iosb;
	STATIC_OBJECT_ATTRIBUTES(oa, "\\device\\69766781178D422cA183775611A8EE55");

	return 0 <= NtOpenFile(&g_hDrv, SYNCHRONIZE, &oa, &iosb, FILE_SHARE_VALID_FLAGS, FILE_SYNCHRONOUS_IO_NONALERT);
}

void DumpToken(HWND hwnd, HANDLE hToken);
void DumpObjectSecurity(HWND hwnd, HANDLE hObject);
void ShowXY(void (*fn)(HWND , HANDLE), HANDLE hObject, PCWSTR caption, HWND hwndParent, HFONT hFont);

NTSTATUS SetLowLevel(HANDLE hToken)
{
	TOKEN_MANDATORY_LABEL tml = { { alloca(RtlLengthRequiredSid(1)), SE_GROUP_INTEGRITY|SE_GROUP_INTEGRITY_ENABLED } };
	static SID_IDENTIFIER_AUTHORITY LabelAuthority = SECURITY_MANDATORY_LABEL_AUTHORITY;
	RtlInitializeSid(tml.Label.Sid, &LabelAuthority, 1);
	*RtlSubAuthoritySid(tml.Label.Sid, 0) = SECURITY_MANDATORY_LOW_RID;
	return NtSetInformationToken(hToken, TokenIntegrityLevel, &tml, sizeof(tml));
}

NTSTATUS GetLastNtStatus(BOOL fOk)
{
	if (fOk) return STATUS_SUCCESS;
	NTSTATUS status = RtlGetLastNtStatus();
	ULONG dwError = GetLastError();
	return RtlNtStatusToDosErrorNoTeb(status) == dwError ? status : HRESULT_FROM_WIN32(dwError);
}

EXTERN_C NTSYSCALLAPI NTSTATUS NTAPI NtCreateToken(
	_Out_ PHANDLE  	TokenHandle,
	_In_ ACCESS_MASK  	DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES  	ObjectAttributes,
	_In_ TOKEN_TYPE  	TokenType,
	_In_ PLUID  	AuthenticationId,
	_In_ PLARGE_INTEGER  	ExpirationTime,
	_In_ PTOKEN_USER  	User,
	_In_ PTOKEN_GROUPS  	Groups,
	_In_ PTOKEN_PRIVILEGES  	Privileges,
	_In_opt_ PTOKEN_OWNER  	Owner,
	_In_ PTOKEN_PRIMARY_GROUP  	PrimaryGroup,
	_In_opt_ PTOKEN_DEFAULT_DACL  	DefaultDacl,
	_In_ PTOKEN_SOURCE  	TokenSource 
	);

NTSTATUS CreateTrustedToken(HANDLE hToken, PHANDLE phToken)
{
	NTSTATUS status;
	PVOID stack = alloca(guz);
	PVOID buf = 0;
	ULONG cb = 0, rcb;

	struct {
		PTOKEN_GROUPS ptg;
		PTOKEN_SOURCE ptsrc;
		PTOKEN_STATISTICS pts;
		PTOKEN_OWNER pto;
		PTOKEN_USER ptu;
		PTOKEN_PRIMARY_GROUP ptpg;
		PTOKEN_DEFAULT_DACL ptdd;
		PTOKEN_PRIVILEGES ptp;
	} s;

	void** ppv = (void**)&s.ptp;

	static const ULONG rcbV[] = {
		sizeof(TOKEN_GROUPS)+0x80,
		sizeof(TOKEN_SOURCE),
		sizeof(TOKEN_STATISTICS),
		sizeof(TOKEN_OWNER) + 0x40,
		sizeof(TOKEN_USER) + 0x40,
		sizeof(TOKEN_PRIMARY_GROUP) + 0x40,
		sizeof(TOKEN_DEFAULT_DACL)+0x80,
		sizeof(TOKEN_PRIVILEGES)+0x80,
	};

	static TOKEN_INFORMATION_CLASS TokenInformationClassV[] = { 
		TokenGroups, 
		TokenSource,
		TokenStatistics,
		TokenOwner,
		TokenUser,
		TokenPrimaryGroup,
		TokenDefaultDacl, 
		TokenPrivileges, 
	};

	ULONG n = _countof(TokenInformationClassV);

	do 
	{
		TOKEN_INFORMATION_CLASS TokenInformationClas = TokenInformationClassV[--n];

		rcb = rcbV[n], cb = 0;

		do 
		{
			if (cb < rcb)
			{
				cb = RtlPointerToOffset(buf = alloca(rcb - cb), stack);
			}

			status = NtQueryInformationToken(hToken, TokenInformationClas, buf, cb, &rcb);

		} while (status == STATUS_BUFFER_TOO_SMALL);

		if (0 > status)
		{
			return status;
		}

		*(ppv--) = buf, stack = buf;

	} while (n);

	// reserve stack space for extend groups
	alloca(sizeof(SID_AND_ATTRIBUTES));

	static const SID_IDENTIFIER_AUTHORITY IdentifierAuthority = SECURITY_NT_AUTHORITY;

	PSID Sid = alloca(RtlLengthRequiredSid(SECURITY_SERVICE_ID_RID_COUNT));

	RtlInitializeSid(Sid, const_cast<PSID_IDENTIFIER_AUTHORITY>(&IdentifierAuthority), SECURITY_SERVICE_ID_RID_COUNT);

	*RtlSubAuthoritySid(Sid, 0) = SECURITY_SERVICE_ID_BASE_RID;
	*RtlSubAuthoritySid(Sid, 1) = SECURITY_TRUSTED_INSTALLER_RID1;
	*RtlSubAuthoritySid(Sid, 2) = SECURITY_TRUSTED_INSTALLER_RID2;
	*RtlSubAuthoritySid(Sid, 3) = SECURITY_TRUSTED_INSTALLER_RID3;
	*RtlSubAuthoritySid(Sid, 4) = SECURITY_TRUSTED_INSTALLER_RID4;
	*RtlSubAuthoritySid(Sid, 5) = SECURITY_TRUSTED_INSTALLER_RID5;

	PSID_AND_ATTRIBUTES Groups = s.ptg->Groups - 1;
	PTOKEN_GROUPS ptg = CONTAINING_RECORD(Groups, TOKEN_GROUPS, Groups);
	ptg->GroupCount = (cb = s.ptg->GroupCount) + 1;
	Groups->Sid = Sid;
	Groups->Attributes = SE_GROUP_ENABLED|SE_GROUP_ENABLED_BY_DEFAULT|SE_GROUP_OWNER;

	if (cb)
	{
		do 
		{
			if (((++Groups)->Attributes & (SE_GROUP_INTEGRITY|SE_GROUP_INTEGRITY_ENABLED)) == (SE_GROUP_INTEGRITY|SE_GROUP_INTEGRITY_ENABLED))
			{
				static const SID_IDENTIFIER_AUTHORITY LabelAuthority = SECURITY_MANDATORY_LABEL_AUTHORITY;
				if (*RtlSubAuthorityCountSid(Sid = Groups->Sid) == 1 &&
					!memcmp(RtlIdentifierAuthoritySid(Sid), &LabelAuthority, sizeof(SID_IDENTIFIER_AUTHORITY)))
				{
					*RtlSubAuthoritySid(Sid, 0) = SECURITY_MANDATORY_SYSTEM_RID;
				}
				break;
			}
		} while (--cb);
	}

	return NtCreateToken(phToken, TOKEN_ALL_ACCESS, 0, TokenPrimary, 
		&s.pts->AuthenticationId, &s.pts->ExpirationTime, 
		s.ptu, ptg, s.ptp, s.pto, s.ptpg, s.ptdd, s.ptsrc);
}

NTSTATUS CreateProcessEx(HANDLE hProcess, 
						 PCWSTR lpApplicationName, 
						 PWSTR lpCommandLine, 
						 DWORD dwCreationFlags, 
						 PVOID lpEnvironment,
						 PCWSTR lpCurrentDirectory,
						 STARTUPINFOW* si, 
						 PROCESS_INFORMATION* pi)
{
	HANDLE hToken;
	NTSTATUS status = NtOpenProcessToken(hProcess, TOKEN_QUERY|TOKEN_DUPLICATE|TOKEN_ASSIGN_PRIMARY, &hToken);

	if (0 > status)
	{
		HANDLE hToken2;
		if (0 <= (status = NtOpenProcessToken(hProcess, TOKEN_QUERY|TOKEN_DUPLICATE, &hToken2)))
		{
			status = NtDuplicateToken(hToken2, TOKEN_ASSIGN_PRIMARY|TOKEN_QUERY|TOKEN_DUPLICATE, 
				0, FALSE, TokenPrimary, &hToken);

			NtClose(hToken2);
		}
	}

	if (0 <= status)
	{
		status = GetLastNtStatus(CreateProcessAsUserW(hToken, lpApplicationName, 
			lpCommandLine, 0, 0, 0, dwCreationFlags, lpEnvironment, lpCurrentDirectory, si, pi));

		NtClose(hToken);
	}

	return status;
}

NTSTATUS CreateProcessEx(HANDLE hProcess, 
					   ULONG TargetSessionId, 
					   ULONG ProcessSessionId, 
					   LONG Flags,
					   PCWSTR lpApplicationName, 
					   PWSTR lpCommandLine, 
					   DWORD dwCreationFlags, 
					   PVOID lpEnvironment,
					   PCWSTR lpCurrentDirectory,
					   STARTUPINFOW* si, 
					   PROCESS_INFORMATION* pi)
{
	HANDLE hToken, hNewToken;

	NTSTATUS status = NtOpenProcessToken(hProcess, 
		_bittest(&Flags, oTrustedIntaller) ?  TOKEN_QUERY_SOURCE|TOKEN_QUERY : TOKEN_DUPLICATE, &hToken);

	if (0 <= status)
	{
		status = _bittest(&Flags, oTrustedIntaller) ? CreateTrustedToken(hToken, &hNewToken) :
			NtDuplicateToken(hToken, TOKEN_QUERY|TOKEN_DUPLICATE|TOKEN_ASSIGN_PRIMARY|
			TOKEN_ADJUST_SESSIONID|TOKEN_ADJUST_DEFAULT, 0, FALSE, TokenPrimary, &hNewToken);

		NtClose(hToken);

		if (0 <= status)
		{
			if (_bittest(&Flags, oTrustedIntaller))
			{
				ProcessSessionId = 0;
			}

			if (TargetSessionId != ProcessSessionId)
			{
				// need TOKEN_ADJUST_SESSIONID | TOKEN_ADJUST_DEFAULT
				status = NtSetInformationToken(hNewToken, TokenSessionId, &TargetSessionId, sizeof(TargetSessionId));
			}

			if (0 <= status && _bittest(&Flags, oLowLevel))
			{
				// need TOKEN_ADJUST_DEFAULT
				status = SetLowLevel(hNewToken);
			}

			if (0 <= status)
			{
				// need TOKEN_QUERY|TOKEN_DUPLICATE|TOKEN_ASSIGN_PRIMARY
				status = GetLastNtStatus(CreateProcessAsUser(hNewToken, lpApplicationName, 
					lpCommandLine, 0, 0, 0, dwCreationFlags, 
					lpEnvironment, lpCurrentDirectory, si, pi));
			}
			NtClose(hNewToken);
		}
	}

	return status;
}

NTSTATUS CreateProcessEx(PCLIENT_ID cid, 
						 ULONG TargetSessionId, 
						 ULONG ProcessSessionId, 
						 LONG Flags,
						 PCWSTR lpApplicationName, 
						 PWSTR lpCommandLine, 
						 DWORD dwCreationFlags, 
						 PVOID lpEnvironment,
						 PCWSTR lpCurrentDirectory,
						 STARTUPINFOEXW* si, 
						 PROCESS_INFORMATION* pi)
{
	PVOID stack = alloca(guz);
	SIZE_T size = max(0x30, sizeof(EEF));
	ULONG cb = 0;

	do 
	{
		if (cb < size)
		{
			size = cb = RtlPointerToOffset(si->lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)alloca(size - cb), stack);
		}

		if (InitializeProcThreadAttributeList(si->lpAttributeList, 1, 0, &size))
		{
			HANDLE hProcess;

			NTSTATUS status = GetLastNtStatus(UpdateProcThreadAttribute(si->lpAttributeList, 0, 
				PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hProcess, sizeof(hProcess), 0, 0));

			if (0 <= status)
			{
				if (_bittestandreset(&Flags, oFrozen))
				{
					goto __f;
				}
				status = MyOpenProcess(&hProcess, PROCESS_CREATE_PROCESS|PROCESS_QUERY_LIMITED_INFORMATION, &zoa, cid);

				if (status == STATUS_ACCESS_DENIED)
				{
__f:
					status = MyOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION, &zoa, cid);
				}
				else
				{
					dwCreationFlags |= EXTENDED_STARTUPINFO_PRESENT;
				}

				if (0 <= status)
				{
					status = Flags || TargetSessionId != ProcessSessionId ? 
						CreateProcessEx(
						hProcess, 
						TargetSessionId, 
						ProcessSessionId, 
						Flags,
						lpApplicationName, 
						lpCommandLine, 
						dwCreationFlags, 
						lpEnvironment,
						lpCurrentDirectory,
						&si->StartupInfo, 
						pi) : 
					CreateProcessEx(
						hProcess, 
						lpApplicationName, 
						lpCommandLine, 
						dwCreationFlags, 
						lpEnvironment,
						lpCurrentDirectory,
						&si->StartupInfo, 
						pi);

					NtClose(hProcess);
				}
			}

			DeleteProcThreadAttributeList(si->lpAttributeList);

			return status;
		}

	} while (GetLastError() == ERROR_INSUFFICIENT_BUFFER);

	return GetLastNtStatus(FALSE);
}

// since WINBLUE (8.1)
NTSTATUS ShowCmdLine8(PCLIENT_ID cid, HWND hwnd)
{
	HANDLE hProcess;

	NTSTATUS status = NtOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION, &zoa, cid);

	if (0 <= status)
	{
		PVOID stack = alloca(sizeof(WCHAR));

		union {
			PVOID buf;
			PUNICODE_STRING CmdLine;
		};

		ULONG cb = 0, rcb = 512;

		do 
		{
			if (cb < rcb) cb = RtlPointerToOffset(buf = alloca(rcb - cb), stack);

			if (0 <= (status = NtQueryInformationProcess(hProcess, ProcessCommandLineInformation, buf, cb, &rcb)))
			{
				*(PWSTR)RtlOffsetToPointer(CmdLine->Buffer, CmdLine->Length) = 0;
				SetWindowTextW(hwnd, CmdLine->Buffer);
				break;
			}

		} while (status == STATUS_INFO_LENGTH_MISMATCH);

		NtClose(hProcess);
	}

	return status;
}

NTSTATUS ShowCmdLineOld(PCLIENT_ID cid, HWND hwnd)
{
	HANDLE hProcess;
	NTSTATUS status = MyOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, &zoa, cid);
	if (0 <= status)
	{
		PROCESS_BASIC_INFORMATION pbi;
		UNICODE_STRING CmdLine;
		union {
			_RTL_USER_PROCESS_PARAMETERS * ProcessParameters;
			PVOID buf;
			PWSTR psz;
		};

		if (
			0 <= (status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), 0)) &&
			0 <= (status = ZwReadVirtualMemory(hProcess, &((_PEB*)pbi.PebBaseAddress)->ProcessParameters, &ProcessParameters, sizeof(ProcessParameters), 0)) &&
			0 <= (status = ZwReadVirtualMemory(hProcess, &ProcessParameters->CommandLine, &CmdLine, sizeof(CmdLine), 0)) &&
			0 <= (status = ZwReadVirtualMemory(hProcess, CmdLine.Buffer, buf = alloca(CmdLine.Length + sizeof(WCHAR)), CmdLine.Length, 0))
			)
		{
			*(PWSTR)RtlOffsetToPointer(psz, CmdLine.Length) = 0;
			SetWindowTextW(hwnd, psz);
		}

		NtClose(hProcess);
	}

	return status;
}

NTSTATUS (*ShowCmdLine)(PCLIENT_ID cid, HWND hwnd);

USHORT g_OSversion;

void InitShowCmdLine()
{
	ShowCmdLine = g_OSversion < _WIN32_WINNT_WINBLUE ? ShowCmdLineOld : ShowCmdLine8;
}

void SetEnv(PCWSTR buf, HWND hwndEdit)
{
	ULONG len = 0, n;
	PCWSTR c = buf;
	do 
	{
		n = 1 + (ULONG)wcslen(c);
		len += n + 1;
		c += n;
	} while (*c);

	PWSTR pv = (PWSTR)alloca(len << 1), sz = pv;

	do 
	{
		n = (ULONG)wcslen(buf);
		memcpy(sz, buf, n << 1);
		sz += n + 2;
		sz[-2] = '\r', sz[-1] = '\n';
		buf += n + 1;
	} while (*buf);

	sz[-2] = 0;

	SetWindowTextW(hwndEdit, pv);
}

NTSTATUS ReadProcessEnv(HANDLE hProcess, PVOID Environment, HWND hwndEdit)
{
	NTSTATUS status;
	MEMORY_BASIC_INFORMATION mbi;

	if (0 > (status = ZwQueryVirtualMemory(hProcess, Environment, MemoryBasicInformation, &mbi, sizeof(mbi), 0))) return status;

	if (mbi.State != MEM_COMMIT || mbi.Type != MEM_PRIVATE)
	{
		return STATUS_UNSUCCESSFUL;
	}

	mbi.RegionSize -= RtlPointerToOffset(mbi.BaseAddress, Environment);

	//Environment must be WCHAR aligned and how minimum 2*sizeof(WCHAR) size
	if (mbi.RegionSize < 2*sizeof(WCHAR) || ((ULONG_PTR)Environment & (__alignof(WCHAR) - 1)))
	{
		return STATUS_UNSUCCESSFUL;
	}

	if (mbi.RegionSize > 0x10000)// >64Kb Environment ??
	{
		mbi.RegionSize = 0x10000;
	}

	PWSTR buf = (PWSTR)alloca(mbi.RegionSize);

	if (0 <= (status = ZwReadVirtualMemory(hProcess, Environment, buf, mbi.RegionSize, 0)))
	{
		*(PULONG)RtlOffsetToPointer(buf, mbi.RegionSize - sizeof(ULONG)) = 0;

		SetEnv(buf, hwndEdit);
		return STATUS_SUCCESS;
	}

	return status;
}

NTSTATUS ReadProcessEnvNative(HANDLE hProcess, HWND hwndEdit)
{
	NTSTATUS status;
	PROCESS_BASIC_INFORMATION pbi;
	_RTL_USER_PROCESS_PARAMETERS* ProcessParameters;
	PVOID Environment;

	if (
		0 > (status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), 0))
		||
		0 > (status = ZwReadVirtualMemory(hProcess, &pbi.PebBaseAddress->ProcessParameters, &ProcessParameters, sizeof(PVOID), 0))
		||
		0 > (status = ZwReadVirtualMemory(hProcess, &ProcessParameters->Environment, &Environment, sizeof(PVOID), 0))
		) 
		return status;

	return ReadProcessEnv(hProcess, Environment, hwndEdit);
}

#if 0

NTSTATUS ReadProcessEnvWow(HANDLE hProcess, PWSTR* ppsz)
{
	ULONG WowPeb, ProcessParameters;
	NTSTATUS status;
	PVOID Environment = 0;

	if (0 > (status = NtQueryInformationProcess(hProcess, ProcessWow64Information, &WowPeb, sizeof(PVOID), 0))) return status;

	if (!WowPeb)
	{
		return STATUS_SUCCESS;
	}

	enum {
		ofs32_ProcessParameters = 0x10,
		ofs32_Environment = 0x48
	};

	if (
		0 > (status = ZwReadVirtualMemory(hProcess, RtlOffsetToPointer(WowPeb, ofs32_ProcessParameters), &ProcessParameters, sizeof(ULONG), 0))
		||
		0 > (status = ZwReadVirtualMemory(hProcess, RtlOffsetToPointer(ProcessParameters, ofs32_Environment), &Environment, sizeof(ULONG), 0))
		) 
		return status;

	return ReadProcessEnv(hProcess, Environment, ppsz);
}
#endif

NTSTATUS ReadProcessEnv(HANDLE Pid, HWND hwndEdit)
{
	HANDLE hProcess;
	CLIENT_ID cid = { Pid };
	NTSTATUS status = MyOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, &zoa, &cid);

	if (0 <= status)
	{
		status = ReadProcessEnvNative(hProcess, hwndEdit);
#if 0
		ReadProcessEnvWow(hProcess, ppszWow);
#endif
		NtClose(hProcess);
	}

	return status;
}

class CMyApp
{
	enum {
		e_Env, e_DeskName, e_Dll, e_WorkDir, e_CmdLine, e_AppName, e_EditCount 
	};

	struct HDEBOBJ
	{
		HDEBOBJ* next;
		HANDLE hDebugObject;

		HDEBOBJ(HANDLE hDebugObject) : hDebugObject(hDebugObject) {}
		~HDEBOBJ() { if (HANDLE h = hDebugObject) NtClose(h); }
	} *m_first;

	NTSTATUS _OnDropDownPro(HWND hwndCtl);
	int OnDropDownPro(HWND hwndCtl, HWND hwndDlg = 0);
	void OnDropDownDeb(HWND hwndCtl);
	void OnDropDownWinsta(HWND hwndCtl);
	NTSTATUS OnRun();
	NTSTATUS ShowProcessDACL();
	NTSTATUS ShowProcessToken();
	NTSTATUS SetCmdLine();
	
	HANDLE _hSysToken;
	HFONT _hFont;
	LONG m_Flags;
	HWND m_hWnd, m_hwPro, m_lastEdit, m_CopyEnv, m_hwDeb, m_hwSesId, m_hwndEdit[e_EditCount];
	
	static INT_PTR CALLBACK StartDialogProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
	static INT_PTR CALLBACK DialogProc_(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
	INT_PTR DialogProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
	BOOL OnInitDialog(HWND hwnd);
	void OnCommand(HWND hwnd, int id, HWND hwndCtl, UINT codeNotify);	
	
	void DeleteDebugObjects();
	void OnBrowse(HWND hwndDlg, HWND hwndEdit);

public:
	
	CMyApp();
	~CMyApp();
};

void CMyApp::DeleteDebugObjects()
{
	HDEBOBJ* first = m_first, *item;
	while (first)
	{
		item = first;
		first = first->next;
		delete item;
	}
	m_first = 0;
}

CMyApp::~CMyApp()
{
	DeleteDebugObjects();

	union {
		HGDIOBJ ho;
		HANDLE h;
	};

	if (ho = _hFont) DeleteObject(ho);

	if (h = _hSysToken)
	{
		NtClose(h);
	}
}

CMyApp::CMyApp()
{
	DialogBoxParamW((HINSTANCE)&__ImageBase, 
		MAKEINTRESOURCE(IDD_DIALOG1), HWND_DESKTOP, StartDialogProc, (LPARAM)this);
}

NTSTATUS CMyApp::ShowProcessDACL()
{
	int i = ComboBox_GetCurSel(m_hwPro);	

	if (0 > i)
	{
		return STATUS_INVALID_CID;
	}

	CLIENT_ID cid = { (HANDLE)ComboBox_GetItemData(m_hwPro, i) };

	HANDLE hProcess;
	NTSTATUS status = MyOpenProcess(&hProcess, READ_CONTROL, &zoa, &cid);

	if (0 <= status)
	{
		WCHAR sz[64];
		_snwprintf(sz, _countof(sz), L"%x Process DACL", (ULONG)(ULONG_PTR)cid.UniqueProcess);
		ShowXY(DumpObjectSecurity, hProcess, sz, 0, _hFont);
		NtClose(hProcess);
	}

	return status;
}

NTSTATUS CMyApp::ShowProcessToken()
{
	int i = ComboBox_GetCurSel(m_hwPro);	

	if (0 > i)
	{
		return STATUS_INVALID_CID;
	}

	CLIENT_ID cid = { (HANDLE)ComboBox_GetItemData(m_hwPro, i) };

	HANDLE hProcess, hToken;
	NTSTATUS status = MyOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION, &zoa, &cid);

	if (0 <= status)
	{
		{
			AutoImpesonate ai(_hSysToken);
			status = NtOpenProcessToken(hProcess, TOKEN_QUERY|TOKEN_QUERY_SOURCE|READ_CONTROL, &hToken);
			NtClose(hProcess);
		}

		if (0 <= status)
		{
			WCHAR sz[64];
			_snwprintf(sz, _countof(sz), L"%x Process Token", (ULONG)(ULONG_PTR)cid.UniqueProcess);
			ShowXY(DumpToken, hToken, sz, 0, _hFont);
			NtClose(hToken);
		}
	}

	return status;
}

NTSTATUS CMyApp::SetCmdLine()
{
	int i = ComboBox_GetCurSel(m_hwPro);	

	if (0 > i)
	{
		return STATUS_INVALID_CID;
	}

	CLIENT_ID cid = { (HANDLE)ComboBox_GetItemData(m_hwPro, i) };
	return ShowCmdLine(&cid, m_hwndEdit[e_CmdLine]);
}

INT_PTR CALLBACK CMyApp::StartDialogProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	if (message == WM_INITDIALOG) 
	{
		SetWindowLongPtr(hwnd, DWLP_USER, (LONG_PTR)lParam);
		SetWindowLongPtr(hwnd, DWLP_DLGPROC, (LONG_PTR)DialogProc_);
		
		SendMessage(hwnd, WM_SETICON, ICON_BIG, (LPARAM)LoadImage((HINSTANCE)&__ImageBase, 
			MAKEINTRESOURCE(IDI_ICON1), IMAGE_ICON, 32, 32, LR_SHARED));
		
		SendMessage(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)LoadImage((HINSTANCE)&__ImageBase, 
			MAKEINTRESOURCE(IDI_ICON1), IMAGE_ICON, 16, 16, LR_SHARED));

		if (g_xp)
		{
			EnableWindow(GetDlgItem(hwnd, IDC_CHECK1), FALSE);
		}

		return reinterpret_cast<CMyApp*>(lParam)->DialogProc(hwnd, message, wParam, lParam);
	}

	return 0;
}

INT_PTR CALLBACK CMyApp::DialogProc_(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	return reinterpret_cast<CMyApp*>(GetWindowLongPtr(hwnd, DWLP_USER))->DialogProc(hwnd, message, wParam, lParam);
}

void CMyApp::OnDropDownDeb(HWND hwndCtl)
{
	ComboBox_ResetContent(hwndCtl);
	DeleteDebugObjects();
	HANDLE hMyDebObj = 0, hProcess, hDebObj;

	NTSTATUS status;
	DWORD cb = 0x10000, rcb;

	union {
		PVOID pv;
		PSYSTEM_HANDLE_INFORMATION_EX pshti;
	};

	static USHORT ObjectTypeIndex;

	if (!ObjectTypeIndex)
	{
		if (0 > NtCreateDebugObject(&hMyDebObj, SYNCHRONIZE, &zoa, 0))
		{
			return ;
		}
	}

	do 
	{
		status = STATUS_INSUFFICIENT_RESOURCES;

		if (pv = new BYTE[cb += 0x1000])
		{
			if (0 <= (status = ZwQuerySystemInformation(
				SystemExtendedHandleInformation, pv, cb, &cb)))
			{
				if (ULONG_PTR NumberOfHandles = pshti->NumberOfHandles)
				{
					PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles = pshti->Handles;

					ULONG_PTR UniqueProcessId = GetCurrentProcessId();

					if (!ObjectTypeIndex)
					{
						do 
						{
							if (Handles->UniqueProcessId == UniqueProcessId && Handles->HandleValue == (ULONG_PTR)hMyDebObj)
							{
								ObjectTypeIndex = Handles->ObjectTypeIndex;

								NumberOfHandles = pshti->NumberOfHandles;
								Handles = pshti->Handles;
								goto __0;
							}
						} while (Handles++, --NumberOfHandles);

						goto __1;
					}

__0:
					cb = 0, rcb = 256;
					PVOID stack = alloca(guz);

					union {
						PVOID buf;
						PUNICODE_STRING Name;
					};

					do 
					{
						if (ObjectTypeIndex == Handles->ObjectTypeIndex && Handles->UniqueProcessId != UniqueProcessId)
						{
							if (0 <= NtOpenProcess(&hProcess, g_xp ?
								PROCESS_DUP_HANDLE|PROCESS_QUERY_INFORMATION : PROCESS_DUP_HANDLE|PROCESS_QUERY_LIMITED_INFORMATION, 
								&zoa, &CID((HANDLE)Handles->UniqueProcessId)))
							{
								do 
								{
									if (cb < rcb) cb = RtlPointerToOffset(buf = alloca(rcb - cb), stack);

									if (0 <= (status = ZwQueryInformationProcess(hProcess, ProcessImageFileName, buf, cb, &rcb)))
									{
										PWSTR lpsz = wcsrchr(Name->Buffer, L'\\');

										lpsz = lpsz ? lpsz + 1 : Name->Buffer;

										if (0 <= ZwDuplicateObject(hProcess, (HANDLE)Handles->HandleValue, NtCurrentProcess(),
											&hDebObj, 0, 0, DUPLICATE_SAME_ACCESS))
										{
											if (HDEBOBJ *item = new HDEBOBJ(hDebObj))
											{
												WCHAR sz[128];
												_snwprintf(sz, 128, L"%04X.%04X %s", 
													(ULONG)(ULONG_PTR)Handles->UniqueProcessId, 
													(ULONG)(ULONG_PTR)Handles->HandleValue, lpsz);
												item->hDebugObject = hDebObj;
												if (0 > ComboBox_AddStringEx(hwndCtl, sz, item)) delete item;
												else
												{
													item->next = m_first;
													m_first = item;
													hDebObj = 0;
												} 
											}
											else
											{
												NtClose(hDebObj);
											}
										}
									}

								} while(status == STATUS_INFO_LENGTH_MISMATCH);

								NtClose(hProcess);
							}
						}
					} while (Handles++, --NumberOfHandles);
				}
			}
__1:
			delete [] pv;
		}

	} while (STATUS_INFO_LENGTH_MISMATCH == status);
	
	if (hMyDebObj)
	{
		NtClose(hMyDebObj);
	}
}

BOOL CMyApp::OnInitDialog(HWND hwnd)
{
	//SetEnv((PCWSTR)RtlGetCurrentPeb()->ProcessParameters->Environment, GetDlgItem(hwnd, IDC_EDIT6));

	m_lastEdit = 0, m_hWnd = hwnd;

	m_CopyEnv = GetDlgItem(hwnd, IDC_BUTTON3);
	m_hwPro = GetDlgItem(hwnd, IDC_COMBO1);
	m_hwDeb = GetDlgItem(hwnd, IDC_COMBO2);
	m_hwSesId = GetDlgItem(hwnd, IDC_COMBO3);
	ComboBox_SetMinVisible(m_hwPro, 16);
	ComboBox_SetCurSel(m_hwPro, OnDropDownPro(m_hwPro, hwnd));

	ULONG m;
	RtlGetNtVersionNumbers(&m, 0, 0);

	NONCLIENTMETRICS ncm = { m < 6 ? sizeof(NONCLIENTMETRICS) - 4 : sizeof(NONCLIENTMETRICS) };
	if (SystemParametersInfo(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0))
	{
		ncm.lfCaptionFont.lfHeight = -ncm.iMenuHeight;
		ncm.lfCaptionFont.lfWeight = FW_NORMAL;
		ncm.lfCaptionFont.lfQuality = CLEARTYPE_QUALITY;
		ncm.lfCaptionFont.lfPitchAndFamily = FIXED_PITCH|FF_MODERN;
		wcscpy(ncm.lfCaptionFont.lfFaceName, L"Courier New");

		_hFont = CreateFontIndirect(&ncm.lfCaptionFont);
	}

	ULONG n = e_EditCount;
	do 
	{	
		if (HWND hwndCtl = GetDlgItem(hwnd, IDC_EDIT6 - --n))
		{
			if (n == e_DeskName)
			{
				COMBOBOXINFO ci = { sizeof(ci) };
				if (!GetComboBoxInfo(hwndCtl, &ci) || !ci.hwndItem) return FALSE;
				hwndCtl = ci.hwndItem;
			}

			m_hwndEdit[n] = hwndCtl;
			continue;
		}
		return FALSE;

	} while (n);

	return TRUE;
}

struct EnumDeskContext 
{
	HWND hwndCombo;
	PWSTR lpszWindowStation;
	SIZE_T cch;
};

BOOL CALLBACK EnumDesktopProc(
							  __in  PWSTR lpszDesktop,
							  __in  LPARAM lParam
							  )
{
	SIZE_T cch = wcslen(lpszDesktop) + reinterpret_cast<EnumDeskContext*>(lParam)->cch;
	PWSTR buf = (PWSTR)alloca(cch * sizeof(WCHAR));
	_snwprintf(buf, cch, L"%s\\%s", reinterpret_cast<EnumDeskContext*>(lParam)->lpszWindowStation, lpszDesktop);
	ComboBox_AddString(reinterpret_cast<EnumDeskContext*>(lParam)->hwndCombo, buf);

	return TRUE;
}

BOOL CALLBACK EnumWindowStationProc(
									__in  PWSTR lpszWindowStation,
									__in  LPARAM lParam
									)
{
	if (HWINSTA hWinSta = OpenWindowStationW(lpszWindowStation, FALSE, WINSTA_ENUMDESKTOPS ))
	{
		reinterpret_cast<EnumDeskContext*>(lParam)->cch = wcslen(lpszWindowStation) + 2;
		reinterpret_cast<EnumDeskContext*>(lParam)->lpszWindowStation = lpszWindowStation;
		EnumDesktopsW(hWinSta, EnumDesktopProc, lParam);
		CloseWindowStation(hWinSta);
	}

	return TRUE;
}

void CMyApp::OnDropDownWinsta(HWND hwndCtl)
{
	ComboBox_ResetContent(hwndCtl);
	EnumDeskContext ctx;
	ctx.hwndCombo = hwndCtl;
	EnumWindowStationsW(EnumWindowStationProc, (LPARAM)&ctx);
}

HRESULT OnBrowseI(_In_ HWND hwndDlg, 
				  _In_ UINT cFileTypes, 
				  _In_ const COMDLG_FILTERSPEC *rgFilterSpec, 
				  _Out_ PWSTR* ppszFilePath, 
				  _In_ UINT iFileType = 0)
{
	IFileDialog *pFileOpen;

	HRESULT hr = CoCreateInstance(__uuidof(FileOpenDialog), NULL, CLSCTX_ALL, IID_PPV_ARGS(&pFileOpen));

	if (SUCCEEDED(hr))
	{
		pFileOpen->SetOptions(FOS_NOVALIDATE|FOS_NOTESTFILECREATE|
			FOS_NODEREFERENCELINKS|FOS_DONTADDTORECENT|FOS_FORCESHOWHIDDEN);

		if (0 <= (hr = pFileOpen->SetFileTypes(cFileTypes, rgFilterSpec)) && 
			0 <= (hr = pFileOpen->SetFileTypeIndex(1 + iFileType)) && 
			0 <= (hr = pFileOpen->Show(hwndDlg)))
		{
			IShellItem *pItem;
			hr = pFileOpen->GetResult(&pItem);

			if (SUCCEEDED(hr))
			{
				hr = pItem->GetDisplayName(SIGDN_FILESYSPATH, ppszFilePath);
				pItem->Release();
			}
		}
		pFileOpen->Release();
	}

	return hr;
}

void CMyApp::OnBrowse(HWND hwndDlg, HWND hwndEdit)
{
	PWSTR pszFilePath;
	static const COMDLG_FILTERSPEC rgSpec[] =
	{ 
		{ L"Executable", L"*.exe" },
		{ L"Crash Dumps", L"*.dll" },
		{ L"All files", L"*" },
	};
	
	UINT iFileType;
	switch (GetDlgCtrlID(m_lastEdit))
	{
	case IDC_EDIT1:
		iFileType = 0;
		break;
	case IDC_EDIT4:
		iFileType = 1;
		break;
	default:
		iFileType = 2;
	}
	HRESULT hr = OnBrowseI(hwndDlg, _countof(rgSpec), rgSpec, &pszFilePath, iFileType);

	if (SUCCEEDED(hr))
	{
		SetWindowTextW(hwndEdit, pszFilePath);
		CoTaskMemFree(pszFilePath);
	}
	m_lastEdit = hwndEdit;
	SetFocus(hwndEdit);
}

INT_PTR CMyApp::DialogProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{	
	union {
		int i;
		BOOL f;
		NTSTATUS status;
		HDEBOBJ* p;
	};

	switch(message) 
	{
	case WM_INITDIALOG:
		if (!OnInitDialog(hwnd)) EndDialog(hwnd, -1);
		return TRUE;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDCANCEL:
			EndDialog(hwnd, 0);
			break;
		case MAKEWPARAM(IDC_EDIT1, EN_SETFOCUS):
		case MAKEWPARAM(IDC_EDIT2, EN_SETFOCUS):
		case MAKEWPARAM(IDC_EDIT3, EN_SETFOCUS):
		case MAKEWPARAM(IDC_EDIT4, EN_SETFOCUS):
			m_lastEdit = (HWND)lParam;
			break;

		case MAKEWPARAM(IDC_EDIT5, CBN_DROPDOWN):
			OnDropDownWinsta((HWND)lParam);
			break;

		case MAKEWPARAM(IDC_COMBO1, CBN_CLOSEUP):
			f = 0 <= ComboBox_GetCurSel((HWND)lParam);
			message = 5;
			do 
			{
				EnableWindow(GetDlgItem (hwnd, IDC_BUTTON2 + --message), f);
			} while (message);
			break;

		case MAKEWPARAM(IDC_COMBO1, CBN_DROPDOWN):
			OnDropDownPro((HWND)lParam);
			break;

		case MAKEWPARAM(IDC_COMBO2, CBN_DROPDOWN):
			OnDropDownDeb((HWND)lParam);
			break;

		case MAKEWPARAM(IDC_BUTTON3, BN_CLICKED):
			if (0 <= (i = ComboBox_GetCurSel(m_hwPro)))
			{
				if (0 > (status = ReadProcessEnv((HANDLE)ComboBox_GetItemData(m_hwPro, i), m_hwndEdit[e_Env])))
				{
					DisplayStatus(status, L"ReadProcessEnv", hwnd);//
				}
			}
			break;

		case MAKEWPARAM(IDC_BUTTON2, BN_CLICKED):
			if (0 > (status = OnRun())) 
			{
				DisplayStatus(status, L"CreateProcess", hwnd);//
			}
			break;
		case MAKEWPARAM(IDC_BUTTON1, BN_CLICKED):
			if (m_lastEdit)
			{
				OnBrowse(hwnd, m_lastEdit);
			}
			else
			{
				MessageBeep((UINT)-1);
				return 0;
			}
			break;

		case MAKEWPARAM(IDC_BUTTON4, BN_CLICKED):
			if (0 > (status = ShowProcessToken())) 
			{
				DisplayStatus(status, L"ShowProcessToken", hwnd);//
			}
			break;
		case MAKEWPARAM(IDC_BUTTON5, BN_CLICKED):
			if (0 > (status = ShowProcessDACL())) 
			{
				DisplayStatus(status, L"ShowProcessDACL", hwnd);//
			}
			break;

		case MAKEWPARAM(IDC_BUTTON6, BN_CLICKED):
			if (0 > (status = SetCmdLine())) 
			{
				DisplayStatus(status, L"SetCmdLine", hwnd);//
			}
			break;

		case MAKEWPARAM(IDC_CHECK1, BN_CLICKED):
			if (SendMessage((HWND)lParam, BM_GETCHECK, 0, 0) == BST_CHECKED)
			{
				CheckDlgButton(hwnd, IDC_CHECK2, BST_UNCHECKED);
				_bittestandset(&m_Flags, oLowLevel);
				_bittestandreset(&m_Flags, oTrustedIntaller);
			}
			else
			{
				_bittestandreset(&m_Flags, oLowLevel);
			}
			break;

		case MAKEWPARAM(IDC_CHECK2, BN_CLICKED):
			if (SendMessage((HWND)lParam, BM_GETCHECK, 0, 0) == BST_CHECKED)
			{
				CheckDlgButton(hwnd, IDC_CHECK1, BST_UNCHECKED);
				_bittestandset(&m_Flags, oTrustedIntaller);
				_bittestandreset(&m_Flags, oLowLevel);
			}
			else
			{
				_bittestandreset(&m_Flags, oTrustedIntaller);
			}
			break;
		}
		break;
	}
	return 0;
}

BOOLEAN IsAlreadyExistSessionId(SYSTEM_PROCESS_INFORMATION* sp, SYSTEM_PROCESS_INFORMATION* cur, ULONG SessionId)
{
	ULONG NextEntryOffset = 0;
	do 
	{
		(ULONG_PTR&)sp += NextEntryOffset;

		if (sp == cur)
		{
			return FALSE;
		}

		if (sp->SessionId == SessionId)
		{
			return TRUE;
		}

	} while (NextEntryOffset = sp->NextEntryOffset);

	__debugbreak();

	return 0;
}

int CMyApp::OnDropDownPro(HWND hwndCtl, HWND hwndDlg )
{
	ComboBox_ResetContent(hwndCtl);
	ComboBox_ResetContent(m_hwSesId);
	
	HWND hwSesId = m_hwSesId;
	LONG SessionMask = 0;
	NTSTATUS status;
	DWORD cb = 0x10000, rcb;

	union {
		PVOID pv;
		ULONG_PTR pb;
		SYSTEM_PROCESS_INFORMATION* sp;
	};

	ULONG SessionId, MySessionId, LastSessionId = 0;
	int index = -1, i;

	ProcessIdToSessionId(GetCurrentProcessId(), &MySessionId);
	PROCESS_EXTENDED_BASIC_INFORMATION pebi = { sizeof(pebi) };
	CLIENT_ID cid = { };

	do 
	{
		status = STATUS_INSUFFICIENT_RESOURCES;

		if (PBYTE buf = new BYTE[cb += 0x1000])
		{
			if (0 <= (status = NtQuerySystemInformation(SystemProcessInformation, buf, cb, &cb)))
			{
				if (hwndDlg)
				{
					if (0 > GetSystemToken(&_hSysToken, buf))
					{
						MessageBox(0, L"GetSystemToken", 0, MB_ICONERROR);

						EndDialog(hwndDlg, 0);

						return -1;
					}
					else
					{
						AutoImpesonate ai(_hSysToken);
						LoadDrv();
					}
				}
				pv = buf;

				cb = 0;
				PVOID stack = alloca(guz);
				PWSTR sz = 0;
				DWORD NextEntryDelta = 0;
				HANDLE id = (HANDLE)GetCurrentProcessId();
				do
				{
					pb += NextEntryDelta;

					if (!sp->UniqueProcessId) {
						sp->SessionId = MAXULONG;
						continue;
					}
					
					cid.UniqueProcess = (HANDLE)(ULONG_PTR)sp->UniqueProcessId;
					HANDLE hProcess;
					WCHAR c = ' ', d = ' ', f = ' ';

					if (0 <= NtOpenProcess(&hProcess, g_xp ? PROCESS_QUERY_INFORMATION : PROCESS_QUERY_LIMITED_INFORMATION, &zoa, &cid))
					{		
#ifdef _WIN64
						PVOID wow;
						if (0 > NtQueryInformationProcess(hProcess, ProcessWow64Information, &wow, sizeof(wow), 0))
						{
							c = '?';
						}
						else if (wow)
						{
							c = '*';
						}
#endif
						if (0 <= NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pebi, sizeof(pebi), &rcb))
						{
							if (pebi.IsProtectedProcess)
							{
								d = '#';
							}
							if (pebi.IsFrozen)
							{
								f = '!';
							}
						}

						NtClose(hProcess);
					}

					rcb = sp->ImageName.Length + 128;

					if (cb < rcb) cb = RtlPointerToOffset(sz = (PWSTR)alloca(rcb - cb), stack);

					SessionId = sp->SessionId;

					swprintf_s(sz, cb >> 1, L"%04X[%04X] %u %c%c%c %wZ", 
						(ULONG)(ULONG_PTR)sp->UniqueProcessId, 
						(ULONG)(ULONG_PTR)sp->InheritedFromUniqueProcessId, 
						SessionId, f, c, d, &sp->ImageName);

					ComboBox_SetItemData(hwndCtl, i = ComboBox_AddString(hwndCtl, sz), sp->UniqueProcessId);

					if (sp->UniqueProcessId == id) index = i;

					if (SessionId < 32 ? !_bittestandset(&SessionMask, SessionId) : 
						LastSessionId != SessionId && !IsAlreadyExistSessionId((SYSTEM_PROCESS_INFORMATION*)buf, sp, SessionId))
					{
						swprintf_s(sz, cb >> 1, L"%u", SessionId);
						ComboBox_SetItemData(hwSesId, i = ComboBox_AddString(hwSesId, sz), SessionId);
						if (MySessionId == SessionId)
						{
							ComboBox_SetCurSel(hwSesId, i);
						}
					}

					LastSessionId = SessionId;

				} while(NextEntryDelta = sp->NextEntryOffset);
			}

			delete [] buf;
		}
		
	} while(status == STATUS_INFO_LENGTH_MISMATCH);

	return index;
}

NTSTATUS ApcInjector(LPCWSTR lpDllName, HANDLE hProcess, HANDLE hThread)
{
	PVOID BaseAddress = 0;
	SIZE_T Size = (wcslen(lpDllName) + 1) << 1, Len = Size;

	NTSTATUS status = ZwAllocateVirtualMemory(hProcess, &BaseAddress, 0, &Size, MEM_COMMIT, PAGE_READWRITE);

	if (0 > status) return status;

	status = ZwWriteVirtualMemory(hProcess, BaseAddress,(LPVOID)lpDllName, (ULONG)Len, 0);

	if (0 > status) 
	{
		ZwFreeVirtualMemory(hProcess, &BaseAddress, &(Size = 0), MEM_RELEASE);
		return status;
	}

#ifdef _WIN64
	PVOID wow;
	if (0 <= (status = ZwQueryInformationProcess(hProcess, ProcessWow64Information, &wow, sizeof(wow), 0)))
	{
		if (wow)
		{
			union {
				PVOID pv;
				PKNORMAL_ROUTINE NormalRoutine;
			};
			
			if (pv = kernel32.funcs[i_LoadLibraryExW].pv)
			{
				status = RtlQueueApcWow64Thread(hThread, NormalRoutine, BaseAddress, 0, 0);
			}

			if (pv = kernel32.funcs[i_VirtualFree].pv)
			{
				RtlQueueApcWow64Thread(hThread, NormalRoutine, BaseAddress, 0, (PVOID)MEM_RELEASE);
			}
		}
		else
		{
			status = ZwQueueApcThread(hThread, (PKNORMAL_ROUTINE)LoadLibraryExW, BaseAddress, 0, 0);
			ZwQueueApcThread(hThread, (PKNORMAL_ROUTINE)VirtualFree, BaseAddress, 0, (PVOID)MEM_RELEASE);
		}
	}
#else
	status = ZwQueueApcThread(hThread,(PKNORMAL_ROUTINE)LoadLibraryExW, BaseAddress, 0, 0);
	ZwQueueApcThread(hThread, (PKNORMAL_ROUTINE)VirtualFree, BaseAddress, 0, (PVOID)MEM_RELEASE);
#endif
	return status;
}

int SetFocusEx(HWND hwndCtl)
{
	SetFocus(hwndCtl);
	MessageBeep((UINT)-1);
	return 0;
}

NTSTATUS CMyApp::OnRun()
{
	NTSTATUS status = STATUS_SUCCESS;

	HWND hwndCtl = m_hwPro;
	int i = ComboBox_GetCurSel(hwndCtl);	
	
	if (0 > i) return STATUS_UNSUCCESSFUL;

	CLIENT_ID cid = { (HANDLE)ComboBox_GetItemData(hwndCtl, i) };

	int len = ComboBox_GetLBTextLen(hwndCtl, i);

	if (len <= 0)
	{
		return STATUS_UNSUCCESSFUL;
	}

	PWSTR str = (PWSTR)alloca((len + 1) * sizeof(WCHAR));

	if (len != ComboBox_GetLBText(hwndCtl, i, str))
	{
		return STATUS_UNSUCCESSFUL;
	}

	if (!(str = wcschr(str, ']')))
	{
		return STATUS_UNSUCCESSFUL;
	}

	ULONG SessionId, ProcessSessionId = wcstoul(str + 2, &str, 10), CurrentProcessId = GetCurrentProcessId();

	if (*str != ' ')
	{
		return STATUS_UNSUCCESSFUL;
	}

	LONG Flags = m_Flags;

	if (str[1] == '!')
	{
		_bittestandset(&Flags, oFrozen);
	}

	SessionId = ProcessSessionId;

	if (0 <= (i = ComboBox_GetCurSel(m_hwSesId)))
	{
		SessionId = (ULONG)ComboBox_GetItemData(m_hwSesId, i);
	}

	PWSTR strA[e_EditCount], lpsz;
	ULONG n = e_EditCount, dwCreationFlags = CREATE_PRESERVE_CODE_AUTHZ_LEVEL;
	do 
	{	
		if (len = GetWindowTextLengthW(hwndCtl = m_hwndEdit[--n]))
		{
			if (GetWindowTextW(hwndCtl, strA[n] = (PWSTR)alloca((len + (n != e_Env ? 1 : 3)) << 1), len + 1) != len)
				return SetFocusEx(hwndCtl);

			if (n == e_Env)
			{
				lpsz = &strA[n][len];
				lpsz[0] = '\r', lpsz[1] = '\n', lpsz[2] = 0;
			}
		}
		else
		{
			if (n == e_AppName)
			{
				return SetFocusEx(hwndCtl);
			}
			strA[n] = 0;
		}

	} while (n);

	if (lpsz = strA[e_Env])
	{
		dwCreationFlags |= CREATE_UNICODE_ENVIRONMENT;

		PWSTR from = 0;
		PBYTE to = 0;
		bool fOk = false;
		do 
		{
			switch (*lpsz)
			{
			case '=':
				fOk = true;
				break;

			case '\r':
				if (!fOk)
				{
					MessageBoxW(m_hwndEdit[e_Env], L"wrong environment format !", 0, MB_ICONWARNING);
					return STATUS_SUCCESS;
				}
				fOk = false;
				*lpsz++ = 0;

				if (to)
				{
					memcpy(to, from, n = RtlPointerToOffset(from, lpsz));
					to += n;
				}
				else
				{
					to = (PBYTE)lpsz;
				}

				from = lpsz + 1;
				break;
			}

		} while (*++lpsz);

		*(PWSTR)to = 0;
	}

	PROCESS_INFORMATION pi;

	if (0 <= (i = ComboBox_GetCurSel(m_hwDeb))) 
	{
		if (HDEBOBJ* p = (HDEBOBJ*)ComboBox_GetItemData(m_hwDeb, i))
		{
			dwCreationFlags |= DEBUG_PROCESS;
			DbgUiSetThreadDebugObject(p->hDebugObject);
		}
	}

	if (strA[e_Dll])
	{
		dwCreationFlags |= CREATE_SUSPENDED;
	}

	STARTUPINFOEXW si = { {sizeof(si), 0, strA[e_DeskName] } };

	if ((ULONG_PTR)cid.UniqueProcess == (ULONG_PTR)CurrentProcessId)
	{
		if (!Flags && SessionId == ProcessSessionId)
		{
			status = GetLastNtStatus(CreateProcessW(strA[e_AppName], strA[e_CmdLine], 0, 0, 0, dwCreationFlags, 
				strA[e_Env], strA[e_WorkDir], &si.StartupInfo, &pi));
		}
		else
		{
			AutoImpesonate ai(_hSysToken);

			status = CreateProcessEx(NtCurrentProcess(), SessionId, ProcessSessionId, Flags, 
				strA[e_AppName], strA[e_CmdLine], dwCreationFlags, strA[e_Env], strA[e_WorkDir], &si.StartupInfo, &pi);
		}
	}
	else
	{
		AutoImpesonate ai(_hSysToken);

		status = CreateProcessEx(&cid, SessionId, ProcessSessionId, Flags, strA[e_AppName], 
			strA[e_CmdLine], dwCreationFlags, strA[e_Env], strA[e_WorkDir], &si, &pi);
	}

	if (0 <= status)
	{
		if (strA[e_Dll]) 
		{
			if (0 > (status = ApcInjector(strA[e_Dll], pi.hProcess, pi.hThread)))
			{
				DisplayStatus(status, L"Fail inject DLL");
			}
		}

		if (dwCreationFlags & CREATE_SUSPENDED)
		{
			ZwResumeThread(pi.hThread, 0);
		}

		NtClose(pi.hThread);		
		NtClose(pi.hProcess);
	} 

	DbgUiSetThreadDebugObject(0);

	return status;
}

extern "C"
{
	extern PVOID __imp_InitializeProcThreadAttributeList, __imp_UpdateProcThreadAttribute, __imp_DeleteProcThreadAttributeList;
}

//#define CPP_FUNCTION __pragma(message("extern " __FUNCDNAME__ " : PROC ; "  __FUNCSIG__))
#define CPP_FUNCTION

BOOL
WINAPI
tmpInitializeProcThreadAttributeList(
								  LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
								  DWORD dwAttributeCount,
								  DWORD dwFlags,
								  PSIZE_T lpSize
								  )
{
	CPP_FUNCTION;
	if (g_xp) 
	{
		SIZE_T cb = *lpSize;
		*lpSize = sizeof(EEF);
		if (cb >= sizeof(EEF))
		{
			new (lpAttributeList) EEF;
			return TRUE;
		}

		SetLastError(ERROR_INSUFFICIENT_BUFFER);
		return FALSE;
	}

	if (PVOID pv = GetProcAddress(GetModuleHandle(L"kernel32"), "InitializeProcThreadAttributeList"))
	{

		__imp_InitializeProcThreadAttributeList = pv;

		return InitializeProcThreadAttributeList(lpAttributeList, dwAttributeCount, dwFlags, lpSize);
	}

	return FALSE;
}

BOOL
WINAPI
tmpUpdateProcThreadAttribute(
						  _Inout_ LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
						  _In_ DWORD dwFlags,
						  _In_ DWORD_PTR Attribute,
						  _In_reads_bytes_opt_(cbSize) PVOID lpValue,
						  _In_ SIZE_T cbSize,
						  _Out_writes_bytes_opt_(cbSize) PVOID lpPreviousValue,
						  _In_opt_ PSIZE_T lpReturnSize
						  )
{
	CPP_FUNCTION;

	if (g_xp) 
	{
		if (Attribute == PROC_THREAD_ATTRIBUTE_PARENT_PROCESS)
		{
			if (cbSize == sizeof(HANDLE))
			{
				reinterpret_cast<EEF*>(lpAttributeList)->InheritFromProcessHandle = *(HANDLE*)lpValue;

				CONTEXT cntx = {};
				cntx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
				cntx.Dr2 = (ULONG_PTR)ZwCreateProcess;
				cntx.Dr3 = (ULONG_PTR)ZwCreateProcessEx;
				cntx.Dr7 = 0x450;

				return 0 <= ZwSetContextThread(NtCurrentThread(), &cntx);
			}
		}

		return FALSE;
	}

	if (PVOID pv = GetProcAddress(GetModuleHandle(L"kernel32"), "UpdateProcThreadAttribute"))
	{

		__imp_UpdateProcThreadAttribute = pv;

		return UpdateProcThreadAttribute(lpAttributeList, dwFlags, Attribute, lpValue, cbSize, lpPreviousValue, lpReturnSize);
	}

	return FALSE;
}

VOID
WINAPI
tmpDeleteProcThreadAttributeList(
							  _Inout_ LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList
							  )
{
	CPP_FUNCTION;
	if (g_xp) return ;
	if (PVOID pv = GetProcAddress(GetModuleHandle(L"kernel32"), "DeleteProcThreadAttributeList"))
	{
		__imp_DeleteProcThreadAttributeList = pv;

		DeleteProcThreadAttributeList(lpAttributeList);
	}
}

#ifdef _X86_

#pragma comment(linker, "/alternatename:___imp_InitializeProcThreadAttributeList=__imp__InitializeProcThreadAttributeList@16")
#pragma comment(linker, "/alternatename:___imp_UpdateProcThreadAttribute=__imp__UpdateProcThreadAttribute@28")
#pragma comment(linker, "/alternatename:___imp_DeleteProcThreadAttributeList=__imp__DeleteProcThreadAttributeList@4")

#else

extern "C"
{
	PVOID __imp_InitializeProcThreadAttributeList = tmpInitializeProcThreadAttributeList;
	PVOID __imp_UpdateProcThreadAttribute = tmpUpdateProcThreadAttribute;
	PVOID __imp_DeleteProcThreadAttributeList = tmpDeleteProcThreadAttributeList;
}
#endif

void ep([[maybe_unused]] PVOID wow)
{	
#ifndef _WIN64
	if (0 > NtQueryInformationProcess(NtCurrentProcess(), ProcessWow64Information, &wow, sizeof(wow), 0) || wow)
	{
		MessageBox(0, L"The 32-bit version of this program is not compatible with the 64-bit Windows you're running.", 
			L"Machine Type Mismatch", MB_ICONWARNING);
		ExitProcess(0);
	}
#else
	DLL_LIST_0::Process(&kernel32);
#endif

	BOOLEAN b;
	RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &b);

	ULONG M, m;
	RtlGetNtVersionNumbers(&M, &m, 0);
	if (g_xp = (M < 6))//_WIN32_WINNT_VISTA;
	{
		if (!RtlAddVectoredExceptionHandler(TRUE, vex))
		{
			ExitProcess(0);
		}
	}

	g_OSversion = (USHORT)((M << 8) + m);
	InitShowCmdLine();
	
	if (0 <= CoInitializeEx(0, COINIT_APARTMENTTHREADED|COINIT_DISABLE_OLE1DDE))
	{
		{ CMyApp theApp{}; }
		CoUninitialize();
	}
	
	ExitProcess(0);
}

_NT_END
