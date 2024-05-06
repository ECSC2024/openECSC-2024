#include "pch.h"
#include "detours.h"
#include <Windows.h>
#include <SubAuth.h>
#include <security.h>
#include <credssp.h>
#include <stdio.h>

#pragma comment(lib, "detours.lib")
#pragma comment(lib, "Secur32.lib")

typedef SECURITY_STATUS(SEC_ENTRY* pAcquireCredentialsHandleW)(LPWSTR, LPWSTR, unsigned long, void*, void*, SEC_GET_KEY_FN, void*, PCredHandle, PTimeStamp);
pAcquireCredentialsHandleW OrigAcquireCredentialsHandleW;
typedef SECURITY_STATUS(SEC_ENTRY* pInitializeSecurityContextW)(PCredHandle, PCtxtHandle, SEC_WCHAR*, unsigned long, unsigned long, unsigned long, PSecBufferDesc, unsigned long, PCtxtHandle, PSecBufferDesc, unsigned long*, PTimeStamp);
pInitializeSecurityContextW OrigInitializeSecurityContextW;
typedef SECURITY_STATUS(SEC_ENTRY* pAcceptSecurityContext)(PCredHandle, PCtxtHandle, PSecBufferDesc, unsigned long, unsigned long, PCtxtHandle, PSecBufferDesc, unsigned long*, PTimeStamp);
pAcceptSecurityContext OrigAcceptSecurityContext;

SECURITY_STATUS SEC_ENTRY
AcquireCredentialsHandleWHijack(
	LPWSTR pszPrincipal,                // Name of principal
	LPWSTR pszPackage,                  // Name of package
	unsigned long fCredentialUse,       // Flags indicating use
	void* pvLogonId,                    // Pointer to logon ID
	void* pAuthData,                    // Package specific data
	SEC_GET_KEY_FN pGetKeyFn,           // Pointer to GetKey() func
	void* pvGetKeyArgument,             // Value to pass to GetKey()
	PCredHandle phCredential,           // (out) Cred Handle
	PTimeStamp ptsExpiry                // (out) Lifetime (optional)
)
{
	printf("[*] AcquireCredentialsHandleW called\n");
	SECURITY_STATUS status = OrigAcquireCredentialsHandleW(
		pszPrincipal,
		pszPackage,
		fCredentialUse,
		pvLogonId,
		pAuthData,
		pGetKeyFn,
		pvGetKeyArgument,
		phCredential,
		ptsExpiry);
	printf("[*] AcquireCredentialsHandleW status: %#lx\n", status);
	return status;
}

SECURITY_STATUS SEC_ENTRY
InitializeSecurityContextWHijack(
	PCredHandle phCredential,               // Cred to base context
	PCtxtHandle phContext,                  // Existing context (OPT)
	SEC_WCHAR* pszTargetName,               // Name of target
	unsigned long fContextReq,              // Context Requirements
	unsigned long Reserved1,                // Reserved, MBZ
	unsigned long TargetDataRep,            // Data rep of target
	PSecBufferDesc pInput,                  // Input Buffers
	unsigned long Reserved2,                // Reserved, MBZ
	PCtxtHandle phNewContext,               // (out) New Context handle
	PSecBufferDesc pOutput,                 // (inout) Output Buffers
	unsigned long* pfContextAttr,           // (out) Context attrs
	PTimeStamp ptsExpiry                    // (out) Life span (OPT)
)
{
	printf("[*] InitializeSecurityContextW called\n");
	SECURITY_STATUS status = OrigInitializeSecurityContextW(
		phCredential,
		phContext,
		pszTargetName,
		fContextReq,
		Reserved1,
		TargetDataRep,
		pInput,
		Reserved2,
		phNewContext,
		pOutput,
		pfContextAttr,
		ptsExpiry);
	printf("[*] InitializeSecurityContextW status: %#lx\n", status);
	return status;
}

SECURITY_STATUS SEC_ENTRY
AcceptSecurityContextHijack(
	PCredHandle phCredential,               // Cred to base context
	PCtxtHandle phContext,                  // Existing context (OPT)
	PSecBufferDesc pInput,                  // Input buffer
	unsigned long fContextReq,              // Context Requirements
	unsigned long TargetDataRep,            // Target Data Rep
	PCtxtHandle phNewContext,               // (out) New context handle
	PSecBufferDesc pOutput,                 // (inout) Output buffers
	unsigned long* pfContextAttr,			// (out) Context attributes
	PTimeStamp ptsExpiry                    // (out) Life span (OPT)
)
{
	printf("[*] AcceptSecurityContext called\n");
	SECURITY_STATUS status = OrigAcceptSecurityContext(
			phCredential,
			phContext,
			pInput,
			fContextReq,
			TargetDataRep,
			phNewContext,
			pOutput,
			pfContextAttr,
			ptsExpiry);
	printf("[*] AcceptSecurityContext status: %#lx\n", status);
	return status;
}

bool InstallHook()
{
	HMODULE secur32 = LoadLibraryW(L"Secur32.dll");

	OrigAcquireCredentialsHandleW = (pAcquireCredentialsHandleW)GetProcAddress(secur32, "AcquireCredentialsHandleW");
	OrigInitializeSecurityContextW = (pInitializeSecurityContextW)GetProcAddress(secur32, "InitializeSecurityContextW");
	OrigAcceptSecurityContext = (pAcceptSecurityContext)GetProcAddress(secur32, "AcceptSecurityContext");

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	DetourAttach(&(PVOID&)OrigAcquireCredentialsHandleW, AcquireCredentialsHandleWHijack);
	DetourAttach(&(PVOID&)OrigInitializeSecurityContextW, InitializeSecurityContextWHijack);
	DetourAttach(&(PVOID&)OrigAcceptSecurityContext, AcceptSecurityContextHijack);

	LONG eCode = DetourTransactionCommit();
	if (eCode != NO_ERROR)
	{
		printf("[-] DetourTransactionCommit failed: %#lx\n", GetLastError());
		return false;
	}
	else
	{
		printf("[*] Hijacked SSPI\n");

		return true;
	}
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		return InstallHook();
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
