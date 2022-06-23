---
title: "[Shellcode development] Resolve function address using IAT instead of EAT - Part 2"
header:
  teaser: "https://farm5.staticflickr.com/4076/4940499208_b79b77fb0a_z.jpg"
categories: 
  - ES
tags:
  - ES
  - Red Team
  - Shellcode
  - Windows PE format
  - IAT
  - Malware
author: Alejandro Pinna
---

Hi to all! After a horrible week with this spanish summer, where there was nothing to do but roast, here we go again, now that temperature is less than 40º it seems we can think and code again. 

During this post we will go on with the first part, where we saw how it is possible to use WinDBG to locate the IAT of a process and find addresses of imported functions. 
Our final goal with this series is to develop a shellcode that will use IAT resolving instead of EAT resolving, and in the third part we will do it using ASM, but today, only as an experiment we will develop a C code that will look for the IAT of a process and will locate the address of a function, once this address is located we will use that to execute arbitrary code in our program without calling the API directly.

As a summary, in the last post we did the following process with WinDBG:

1. Locate TEB
2. Locate PEB
3. Locate ImageBaseAddress in PEB
4. Parse DOS headers
5. Parse NT Headers
6. Parse OptionalHeader
7. Locate _IMAGE_IMPORT_DESCRIPTOR.
8. Find the name of an API in _IMAGE_IMPORT_DESCRIPTOR->OriginalFirstThunk (Import Lookup Table (ILT)) [1]
9. Find the address of that API in _IMAGE_IMPORT_DESCRIPTOR->FirstThunk (Addresses)


## Finding PEB address

Contrarly to what we had to do in WinDBG, in this case we will not need to find TEB address, instead, we will directly find PEB address, for that we will use the NTDLL function **NtQueryInformationProcess** which has the following definition:

```c
__kernel_entry NTSTATUS
NTAPI
NtQueryInformationProcess (
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL
    );
```

We will have to pass it a HANDLE to the process, which in this case will be the current process, that is identified by **0xFFFFFFFF**.
The second we will pass the type of PROCESSINFOCLASS we will get, in our case **ProcessBasicInformation**
After that we will pass a pointer to a PROCESSINFOCLASS structure, which will store the result of the function, in our case it will be a **PROCESS_BASIC_INFORMATION** structure, which has the pointer to the PEB address as we can see in the definition:

```c
typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;
```
The last arguments will be the size of the structure we are passing and a pointer to a unsigned long that will store the length in bytes returned by the function.

In our case we developed a function that will return the address of the PEB as is showed below.

```c
PPEB locate_PEB()
{
	DWORD returnLength;
	PROCESS_BASIC_INFORMATION information;

	NTSTATUS returnValue = NtQueryInformationProcess((HANDLE)0xFFFFFFFF, ProcessBasicInformation, &information, sizeof(PROCESS_BASIC_INFORMATION), &returnLength);
	if (!NT_SUCCESS(returnValue))
	{
		printf("Error: %lu\n", returnValue);
		return 0;
	}
	return  information.PebBaseAddress;

}
```

## Finding IAT from PEB

Once we found the PEB, we will go through it, to locate the ImageBaseAddress of the current process.
To do that, we must have in mind the definition of PEB (in this case it's from winternl, if you need to use PEB for any reason, i recomend you define it by yourself to avoid the Reserved Microsoft~~shit~~).

```c
typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1]; 
    PVOID Reserved3[2]; /*ImageBaseAddress*/
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID Reserved4[3];
    PVOID AtlThunkSListPtr;
    PVOID Reserved5;
    ULONG Reserved6;
    PVOID Reserved7;
    ULONG Reserved8;
    ULONG AtlThunkSListPtr32;
    PVOID Reserved9[45];
    BYTE Reserved10[96];
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
    BYTE Reserved11[128];
    PVOID Reserved12[1];
    ULONG SessionId;
} PEB, *PPEB;
```

As you can see the Microsoft definition of PEB doesn't specify where ImageBaseAddress is, but from WinDBG (really any place in the internet) we can find it's really pointed by Reserved3[1].

With the ImageBaseAddress located, we can start parsing the PE headers, first of all we will parse _IMAGE_DOS_HEADERS to find the address of _IMAGE_NT_HEADERS, and finally _IMAGE_OPTIONAL_HEADER.
When we are in _IMAGE_OPTIONAL_HEADER we will go to _IMAGE_OPTIONAL_HEADER->DataDirectory which stores an array to different internal structures of a PE32 file.
Below we can see where each index of the _IMAGE_DATA_DIRECTORY array is pointing to. [2]

```c
// Directory Entries (16 entries are pre-defined)
#define IMAGE_DIRECTORY_ENTRY_EXPORT         0     /*Export Directory */
#define IMAGE_DIRECTORY_ENTRY_IMPORT         1     /*Import Directory */
#define IMAGE_DIRECTORY_ENTRY_RESOURCE       2     /*Resource Directory */
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION      3     /*Exception Directory */
#define IMAGE_DIRECTORY_ENTRY_SECURITY       4     /*Security Directory */
#define IMAGE_DIRECTORY_ENTRY_BASERELOC      5     /*Base Relocation Table */
#define IMAGE_DIRECTORY_ENTRY_DEBUG          6     /*Debug Directory */
#define IMAGE_DIRECTORY_ENTRY_COPYRIGHT      7     /* (x86 usage) */
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE   7     /* Architecture Specific Data */
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR 	 8     /* RVA of GP */
#define IMAGE_DIRECTORY_ENTRY_TLS            9	   /* TLS Directory */
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10    /* Load Configuration Directory */
#define IMAGE_DIRECTORY_ENTRY_LOAD_BOUND_IMPORT 	11     /* Bound Import Directory in headers */
#define IMAGE_DIRECTORY_ENTRY_LOAD_IAT 				12     /* Import Address Table */
#define IMAGE_DIRECTORY_ENTRY_LOAD_DELAY_IMPORT 	13     /* Delay Load Import Descriptors */
#define IMAGE_DIRECTORY_ENTRY_LOAD_COM_DESCRIPTOR 	14     /* COM Runtime descriptor */
```

In this case we are interested in the Import Directory.

It's important to note that each index of the array is also a structure, which will hold the following elements.

```c
typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
```

So, to find the address of the Import Directory which is described by the _IMAGE_IMPORT_DESCRIPTOR structure, we may access to **_IMAGE_OPTIONAL_HEADER->DataDirectory[1].VirtualAddress**

In our case, the following code will do that work.


```c
LPVOID imageBaseAddress = pPeb->Reserved3[1];
printf("ImageBaseAddress: 0x%X\n", imageBaseAddress);
IMAGE_DOS_HEADER  *pDosHeaders = (IMAGE_DOS_HEADER*)imageBaseAddress;
IMAGE_NT_HEADERS  *ntHeaders = (IMAGE_NT_HEADERS*)(pDosHeaders->e_lfanew + (unsigned long long)imageBaseAddress); /*pDosHeaders-e_lfanew === pDosHeaders+0x03c*/
IMAGE_OPTIONAL_HEADER32 OptionalHeader = ntHeaders->OptionalHeader; /*ntHeaders->OptionalHeader === ntHeaders+0x018*/
_IMAGE_IMPORT_DESCRIPTOR* pImportDescriptor = (_IMAGE_IMPORT_DESCRIPTOR*)((unsigned long long)imageBaseAddress + OptionalHeader.DataDirectory[1].VirtualAddress);
```


## Locating DLLs in the IAT.

The _IMAGE_IMPORT_DESCRIPTOR (aka ImportDescriptor) structure is stored in memory as shows the following diagram.

```
+-------------------------+
|    OriginalFirstThunk   |
|      TimeDateStamp      |
|      ForwarderChain     | --> First DLL in IAT (VCRUNTIME140.DLL)
|       Name of DLL       |
|       FirstThunk        |
+-------------------------+
+-------------------------+
|    OriginalFirstThunk   |
|      TimeDateStamp      |
|      ForwarderChain     | --> Second DLL in IAT (NTDLL.DLL)
|      Name (of DLL)      |
|       FirstThunk        |
+-------------------------+
+-------------------------+
|    OriginalFirstThunk   |
|      TimeDateStamp      |
|      ForwarderChain     | --> Third DLL in IAT (KERNEL32.DLL)
|       Name of DLL       |
|       FirstThunk        |
+-------------------------+
```

So if we want to locate a function imported from KERNEL32.DLL we must previously find where in this array is KERNEL32.DLL ImportDescriptor.

To accomplish that goal, we will loop on every ImportDescriptor, checking if name field is equal to KERNEL32.DLL and if it's not equal, we will go to the next ImportDescritor by adding the size of ImportDescriptor to the previous pointer.

```c
while (strcmp((char*)(pImportDescriptor->Name + (unsigned long long)imageBaseAddress), "KERNEL32.dll") != 0)
{
	pImportDescriptor = (_IMAGE_IMPORT_DESCRIPTOR*)((long*)pImportDescriptor + (sizeof(_IMAGE_IMPORT_DESCRIPTOR)/sizeof(DWORD))); /*go to the next _IMAGE_IMPORT_DESCRIPTOR

	printf("Address is 0x%p\n", pImportDescriptor);

	printf("Name is: %s\n", (char*)(pImportDescriptor->Name + (unsigned long long)imageBaseAddress));

} 
```


Here we can observe the next line, which is probably the most difficult part of this code.

```c
pImportDescriptor = (_IMAGE_IMPORT_DESCRIPTOR*)((byte*)pImportDescriptor + sizeof(_IMAGE_IMPORT_DESCRIPTOR));
```

As we said, we need to go through the ImportDescriptor to find which structure belongs to KERNEL32, so we need to locate the first part of ImportDescriptor (OriginalFirstThunk) and add the size of ImportDescriptor to it in order to reach the OriginalFirstThunk of the next ImportDescriptor.

Graphically we can see it in the next screenshot.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_06_22-shellcode-part-2/memory_importdescriptor.png)

To do that, the first idea that comes to our mind is the following:

```c
pImportDescriptor = (_IMAGE_IMPORT_DESCRIPTOR*)(pImportDescriptor + sizeof(_IMAGE_IMPORT_DESCRIPTOR));
```

But when doing that, we see it's not working correctly, so reviewing it with a disassembler we see what is being done internally.

```c
mov eax,dword ptr ss:[ebp-0x130] ; pImportDescriptor addr in ebp-0x130
add eax,0x190 ; add sizeof(ImportDescriptor)
mov dword ptr ss:[ebp-0x130],eax ; Update pImportDescriptor
```
But we observed in the last screenshot that the size of each structure is 0x14 bytes, so why is it adding 0x190 and not 0x14.

After talking with @ElephantSe4l he realized that it's because C treats each DWORD as 4 bytes in memory, so when you add 1 to a DWORD (memory address) you go to the next DWORD that is 4 bytes farther.

In this case we are treating with a structure which has 0x14 bytes, so when we add the size of the structure it will multiply it by the size of the structure:
**0x14*0x14 = 0x190**

The solution in this case has been to cast the adding operation as a byte, so when we add the size of ImportDescriptor the compiler handles it conveniently.

```c
pImportDescriptor = (_IMAGE_IMPORT_DESCRIPTOR*)((byte*)pImportDescriptor + sizeof(_IMAGE_IMPORT_DESCRIPTOR));
/*mov eax,dword ptr ss:[ebp-0x130] ; pImportDescriptor addr in ebp-0x130
add eax,0x14 ; add sizeof(ImportDescriptor)
mov dword ptr ss:[ebp-0x130],eax ; Update pImportDescriptor
*/
```

## Locating index of name in _IMAGE_IMPORT_BY_NAME


When solvented this troubles we can go on, now we have located which structure belongs to KERNEL32.DLL and we have stored it's address in **pImportDescriptor**, so let's locate where GetProcAddress name is, and locate the address of the function.

As we did in the last part, we need to loop over ImportDescriptor->OriginalFirstThunk (_IMAGE_IMPORT_BY_NAME) which is stored as an array of a structure in memory, the OriginalFirstThunk is a structure which has the following elements.

```c
typedef struct _IMAGE_IMPORT_BY_NAME {
    WORD    Hint;
    CHAR   Name[1];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;
```

It's an easy one, we only need to check if **_IMAGE_IMPORT_BY_NAME->Name == "GetProcAddress"** and store the index of the _IMAGE_IMPORT_BY_NAME array in a variable.
To do that, we will get the RVA of OriginalFirstThunk, we will add it the ImageBaseAddress, then we will be in the array corresponding to _IMAGE_IMPORT_BY_NAME[0], later we loop that array, and check if name is GetProcAddress.

```c
long* relativeIAT = (long*)(pImportDescriptor->OriginalFirstThunk + (unsigned long long)imageBaseAddress); /*Store the address in relativeIAT*/
printf("Data is: %p\n", relativeIAT);

unsigned long index = 0;
_IMAGE_IMPORT_BY_NAME* importByName = (_IMAGE_IMPORT_BY_NAME*)(*relativeIAT + (unsigned long)imageBaseAddress); /*Real IAT in importByName*/

char* name = importByName->Name;

while (strcmp(name, "GetProcAddress") != 0)
{
	relativeIAT = (long*)((byte*)relativeIAT + sizeof(DWORD));  /*Go to the next part of the ARRAY*/
	/*Cast relativeIAT as a byte, so when we add sizeof(DWORD) we go to the next 4 bytes in memory*/
	/*In C every dword has a 4 byte size, so if  you do DWORD+4 really yo are doing DWORD+0x10, instead, if you want to do*/
	/*DWORD+4 you should do DWORD+1 that is DWORD+*/
	importByName = (_IMAGE_IMPORT_BY_NAME*)(*relativeIAT + (unsigned long)imageBaseAddress);
	name = importByName->Name;
	printf("Data is: %s\n", name);
	index += 1;

}
```

## Locating address in IAT.

And our final step, once we have the index of GetProcAddress in the _IMAGE_IMPORT_BY_NAME array, is locating the address of the function in the IAT.

It's going to be really easy, we will need only to get the address of IAT (FirstThunk) and go to the position specified by our previously calculated index.

```c
long* relativeIATAddr = (long*)(pImportDescriptor->FirstThunk + (unsigned long long)imageBaseAddress);
long* addr = relativeIATAddr + counter;
```
In the debugger it's seen below.

```c
mov dword ptr ss:[ebp-0x16C],ecx  ; Address of relativeIATAddr
mov eax,dword ptr ss:[ebp-0x148]  ; index
mov ecx,dword ptr ss:[ebp-0x16C] 
lea edx,dword ptr ds:[ecx+eax*4]  ; load address of relativeIATAddr + inddex in edx
mov dword ptr ss:[ebp-0x178],edx  ; Save address in ebp-0x178
```
And now we have the address of GetProcAddress manually resolved from the IAT.

## Resolving Kernel32.dll base address

To call GetProcAddress in order to resolve functions from kernel32.dll we may first know where kernel32.dll base address is.
To do that we must again parse the PEB structure, to locate the _PEB_LDR_DATA, which is an structure that holds information about loaded modules in the memory of a process.
This structure has the following definition:

```c
typedef struct _PEB_LDR_DATA {
    BYTE Reserved1[8];
    PVOID Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;
```

We can see the last element of the structure, which is of type LIST_ENTRY (linked list) where the first element of the list points to the first element of the **_LDR_DATA_TABLE_ENTRY**

And we must see also the definition of _LDR_DATA_TABLE_ENTRY:

```c
struct _LDR_DATA_TABLE_ENTRY
{
    struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
    struct _LIST_ENTRY InMemoryOrderLinks;                                  //0x8
    struct _LIST_ENTRY InInitializationOrderLinks;                          //0x10
    VOID* DllBase;                                                          //0x18
    VOID* EntryPoint;                                                       //0x1c
    ULONG SizeOfImage;                                                      //0x20
    struct _UNICODE_STRING FullDllName;                                     //0x24
    struct _UNICODE_STRING BaseDllName;                                     //0x2c
    ULONG Flags;                                                            //0x34
    USHORT LoadCount;                                                       //0x38
    USHORT TlsIndex;                                                        //0x3a
    union
    {
        struct _LIST_ENTRY HashLinks;                                       //0x3c
        struct
        {
            VOID* SectionPointer;                                           //0x3c
            ULONG CheckSum;                                                 //0x40
        };
    };
    union
    {
        ULONG TimeDateStamp;                                                //0x44
        VOID* LoadedImports;                                                //0x44
    };
    VOID* EntryPointActivationContext;                                      //0x48
    VOID* PatchInformation;                                                 //0x4c
}; 
```

We see again the first element is a linked list, and the first element of _LIST_ENTRY points to the next _LDR_DATA_TABLE_ENTRY.
Watching this we see we must locate the first Flink of **_PEB_LDR_DATA->InMemoryOrderModuleList->Flink** and then we will be in the first _LDR_DATA_TABLE_ENTRY, where we will check if this is related with Kernel32.dll by checking the _UNICODE_STRING FullDllName, and if it's not, then we will go to the next _LDR_DATA_TABLE_ENTRY by following _LDR_DATA_TABLE_ENTRY->InLoadOrderLinks->Flink doing this process until we reach the _LDR_DATA_TABLE_ENTRY related with Kernel32.dll

We developed a simple function that doest this process.

```c
unsigned long get_kernel32_addr(PEB* pebAddress)
{
	PPEB pPeb = pebAddress;
	_PEB_LDR_DATA *LdrData = pebAddress->Ldr; /*Locate _PEB_LDR_DATA*/
	_LDR_DATA_TABLE_ENTRY* DataTableEntry = (_LDR_DATA_TABLE_ENTRY*)LdrData->InMemoryOrderModuleList.Flink; /*_LDR_DATA_TABLE_ENTRY pointed by _PEB_LDR_DATA->InMemoryOrderModuleList.Flink*/
	long* newDataTableEntry = (long*)((_LDR_DATA_TABLE_ENTRY*)DataTableEntry->Reserved1); /*Next DataTableEntry pointed by _LDR_DATA_TABLE_ENTRY->Reserved1 (equal to Flink)*/
	wchar_t* name;
	HMODULE dllbase;
	long* dllbase_addr;
	do
	{
		name = DataTableEntry->FullDllName.Buffer; /*Name of the DLL pointed by this _LDR_DATA_TABLE_ENTRY structure*/
		dllbase_addr = (long*)DataTableEntry+4; /*Workaround, because winternl sucks*/
		dllbase = (HMODULE)*dllbase_addr; /*DllBase*/
		printf("Address DllBase is: 0x%p\n", DataTableEntry);

		DataTableEntry = (_LDR_DATA_TABLE_ENTRY*)*newDataTableEntry; /*Update current _LDR_DATA_TABLE_ENTRY with position of next _LDR_DATA_TABLE_ENTRY*/
		newDataTableEntry = (long*)((_LDR_DATA_TABLE_ENTRY*)DataTableEntry->Reserved1); /*Update next _LDR_DATA_TABLE_ENTRY*/
	} while (wcscmp(name, L"KERNEL32.DLL") != 0);
	return (unsigned long)dllbase;

}
```




## Resolving WinExec with GetProcAddress and prompt a calc.exe

To end this post, we will use the address of GetProcAddress to resolve WinExec (It's not in the IAT, if not we could do it manually) and execute a calc.exe from that.

Here we must treat the address of GetProcAddress as a function pointer, and we must keep in mind that we have to specify the calling convention of WindowsAPI if we don´t want to break the stack.

```c
typedef UINT WinExec(
	/*[in]*/ LPCSTR lpCmdLine,
	/*[in]*/ UINT   uCmdShow
);

int call_get_proc_address_api(long* address, long Kernel32Handle) /*address = GetProcAddresss, Kernel32Handle = Address of Kernel32.dll*/
{
	long (__stdcall *get_proc_address)(long, const char*) = (long(__stdcall *)(long, const char*)) ((long)*address); /*get_proc_address as a function pointer to address*/
	WinExec *WinExecA = (WinExec*)get_proc_address(Kernel32Handle, "WinExec"); /*Resolve WinExec*/
	printf("Addr in 0x%x\n", *address);
	if (WinExecA == 0)
	{
		printf("GetLastError is: %lu\n", GetLastError());
	}
	unsigned int final_value = WinExecA("calc.exe", SW_NORMAL); /*Call calc.exe from WinExecA
	return final_value;
}
```

## Conclusion

We see how it's possible to resolve address from the IAT using C (like the windows loader would do).
In this case it's only an experiment, because using the resultant asm code (after compiling) is not very useful, due to it will have badchars and will be very big.

We will see in the next part of this series how to do this process using assembly instead of C code, and how in some cases it's easier, for example we will not have to cast data so that the compiler understands it well.

References: 

[1] - <https://0xrick.github.io/win-internals/pe6/#import-lookup-table-ilt>
[2] - <https://dandylife.net/blog/archives/388>











 



 






