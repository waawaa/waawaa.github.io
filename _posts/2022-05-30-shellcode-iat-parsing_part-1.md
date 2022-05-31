---
title: "[Shellcode development] Resolve function address using IAT instead of EAT - Part 1"
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

In this, my very first post after a long long time, we will be reviewing different structures of PE files, those who are in charge of specify which functions must be imported by a PE file, and also those in charge of functions exported by a DLL.

It all started during my EXP-301 training. During one of the modules, custom shellcode development is explained, where DLL's EAT is used to look for useful functions, that will be used to perform further actions.

A very usual approach would be the following:

1. Locate Kernelbase.dll
2. Loop on AddrofNames until you locate GetProcAddress
3. Get the ordinal for GetProcAddress
4. Get the real address of GetProcAddress
5. Locate other functions using GetProcAddress

To do those actions, the following structure must be parsed:

```c
 typedef struct _IMAGE_EXPORT_DIRECTORY {
   ULONG Characteristics;
   ULONG TimeDateStamp;
   USHORT MajorVersion;
   USHORT MinorVersion;
   ULONG Name;
   ULONG Base;
   ULONG NumberOfFunctions;
   ULONG NumberOfNames;
   ULONG AddressOfFunctions;
   ULONG AddressOfNames;
   ULONG AddressOfNameOrdinals;
 } IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
```

This structure stores a pointer to three diferent and important arrays, which are the following:

AddressOfFunctions
AddressOfNames
AddressOfNameOrdinals

As we explained before, you need to carry on with the following steps:

- To start with, you need to loop on the AddressOfNames array, until you locate the index of GetProcAddress string.
- Secondly, you will use that index to locate the ordinal of the function. This ordinal will be an index to the real address of the function inside the AddressofFunctions array.
- Finally, using the ordinal, the real address of the function is extracted from AddressOfFunctions.

Some posts explain very deeply this process, this is one i like so much.

<https://xen0vas.github.io/Win32-Reverse-Shell-Shellcode-part-2-Locate-the-Export-Directory-Table>

During the practice of this technique, an idea came to my mind. Why not use IAT of the exploited process, instead of using the EAT of the Kernel32/Kernelbase DLL ??



## Explanation

First of all, it must be explained that almost every process that is running in a Windows environment, has a Kernel32/Kernelbase DLL image loaded in memory. So, is not a fantasy to think that we can use the IAT of the exploited process to resolve those functions.

During this post, we will be working with two structures consisting on the subsequent.

The first is **_IMAGE_IMPORT_DESCRIPTOR** and holds information about the name of the DLL, a pointer to the IAT, and a pointer to the names of the functions imported.

This is the definition:

```c 
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
   _ANONYMOUS_UNION union {
     ULONG Characteristics;
     ULONG OriginalFirstThunk;
   } DUMMYUNIONNAME;
   ULONG TimeDateStamp;
   ULONG ForwarderChain;
   ULONG Name;
   ULONG FirstThunk;
 } IMAGE_IMPORT_DESCRIPTOR, *PIMAGE_IMPORT_DESCRIPTOR;
```

And the second structure is the own IAT (**_IMAGE_IMPORT_BY_NAME**), that as we will see during this post, is different when the PE image is loaded in memory than when it resides on disk.

In disk it has the following definition:

```c 
typedef struct _IMAGE_IMPORT_BY_NAME {
   USHORT Hint;
   UCHAR Name[1];
 } IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;
```

_IMAGE_IMPORT_BY_NAME is usually known as the IAT.

## Debugging those structures with Windbg and with X32DBG

All the work will be done with WinDBG, but for display ~~mental health~~ reasons, we will use sometimes x32dbg to inspect memory.

To begin, we load our program (**asm_iat_parse.exe**) in windbg emulating a suspended process.

We will se how to calculate the address of IAT, and we will use those steps to compare a process that has not been fully initialized yet with a running process.

For this we use the following command line<code  style="background-color: lightgrey; color:black;"><b>windbg.exe -le:ntdll.dll asm_parse_iat.exe</b></code>

This command line will open asm_parse_iat.exe before RtlUserThreadStart is started, so IAT of the image is still intact.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_05_30-shellcode-part-1/windbg_start.png)


With this, let's proceed to look for the IAT manually using windbg.

We will access the **_TEB** structure, for that we use the **fs:[0]** register.

As we can see, _TEB has a pointer to _PEB in position 0x30

```c
dt _TEB
ntdll!_TEB
   +0x000 NtTib            : _NT_TIB
   +0x01c EnvironmentPointer : Ptr32 Void
   +0x020 ClientId         : _CLIENT_ID
   +0x028 ActiveRpcHandle  : Ptr32 Void
   +0x02c ThreadLocalStoragePointer : Ptr32 Void
   +0x030 ProcessEnvironmentBlock : Ptr32 _PEB
   +0x034 LastErrorValue   : Uint4B
   +0x038 CountOfOwnedCriticalSections : Uint4B
   +0x03c CsrClientThread  : Ptr32 Void
   +0x040 Win32ThreadInfo  : Ptr32 Void
```
So we need to read the content of **fs:[0x30]** to access to ProcessEnvironmentBlock structure


![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_05_30-shellcode-part-1/windbg_get_peb.png)

Having the base address of the image, we will parse **_IMAGE_DOS_HEADER**
But before going on, let's keep the address of the ImageBase in a temporary register of WinDBG 

```c
r @$t0 = poi(poi(fs:[0x30])+0x008)
```

This will be used later to calculate other addresses that are relative to the imageBase direction. Using this we don't need to hardcode addresses and this technique is scalable to other binaries.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_05_30-shellcode-part-1/windbg_get_dos_header_from_TEB.png)

Now we can calculate the offset to _IMAGE_NT_HEADERS, using the position 0x30 of _IMAGE_DOS_HEADER, which stores an offset to _IMAGE_NT_HEADERS and adding the offset to our temporary register

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_05_30-shellcode-part-1/windbg_get_nt_header.png)


Consequently, we will access _IMAGE_OPTIONAL_HEADER->DirectoryEntry, to get the address of _IMAGE_OPTIONAL_HEADER. We use _IMAGE_NT_HEADERS->OptionalHeader which is stored in _IMAGE_NT_HEADERS+0x030

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_05_30-shellcode-part-1/windbg_get_optional_header.png)

And to finish, we just need to get the address of the DataDirectory array, which has in the position 1 (DataDirectory[1]) the address of _IMAGE_IMPORT_DESCRIPTOR.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_05_30-shellcode-part-1/windbg_get_directoryentry_header.png)



To clarify, we must say that to access _IMAGE_IMPORT_DESCRIPTOR we shall access the position 1 of DataDirectory, this array is a structure described as follows.

```c
0:000> dt _IMAGE_DATA_DIRECTORY
ntdll!_IMAGE_DATA_DIRECTORY
   +0x000 VirtualAddress   : Uint4B
   +0x004 Size             : Uint4B
```
So we have to access DataDirectory+0x8 to get the relative address of _IMAGE_IMPORT_DESCRIPTOR, and later this will be added to our temporary register (stored ImageBase) to get the structure.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_05_30-shellcode-part-1/windbg_get_import_descriptor.png)

As a result, with this structure located, we can resolve the name of the DLL, which in this case is VCRUNTIME140.dll

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_05_30-shellcode-part-1/windbg_get_dllname.png)

And we can also get the address of the IAT, that in this case is the same for OriginalFirstThunk and FirstThunk, this happens because the process is not fully initialized, but once the process runs, the FirstThunk will point to function addresses and OriginalFirstThunk will point to IAT (_IMAGE_IMPORT_BY_NAME)


![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_05_30-shellcode-part-1/windbg_get_function_names.png)


After the process is initialized this array will store the same data than now, but the **FirstThunk**, which is in **_IMAGE_IMPORT_DESCRIPTOR+0x10** will have the address of the functions imported, ordered exactly like in _IMAGE_IMPORT_BY_NAME (**OriginalFirstThunk**)

This diagram is a graphical explanation of that idea.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_05_30-shellcode-part-1/IAT_relations.png)

We can see how those address are modified when the process is loading, but instead of using WinDBG, we will use x32dbg, and we will set a hardware breakpoint at **FirstThunk** addresses. 
With this we can observe how the IAT array is overwritten with the real addresses of the functions.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_05_30-shellcode-part-1/iat_pre_breakpoint.png)

The previous image shows how the iat points to the _IMAGE_IMPORT_BY_NAME array before being overrided by the loader, and the next one shows how this looks like after the process has been initialized.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_05_30-shellcode-part-1/iat_post_breakpoint.png)

Finally, we see this address point to the **GetModuleFileName** function, that as we saw before, is the first one that is imported by the executable.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_05_30-shellcode-part-1/iat_post_breakpoint_resolved.png)


## Conclusion

We have seen how import structures (arrays) can be parsed to get the index (position) of the function name in the array, and later use that index in the address array to get the real address of that function.

Additionally, in comparison with resolving addresses using EAT, this method is much easier in comparison with EAT parsing.

In the next part of this series we will see how to do that in C code and assembly level, and how to pop a calc using IAT resolving.

References:
- https://modexp.wordpress.com/2017/01/15/shellcode-resolving-api-addresses/
- https://0xrick.github.io/win-internals/pe6/
- https://dandylife.net/blog/archives/388
- https://xen0vas.github.io/Win32-Reverse-Shell-Shellcode-part-2-Locate-the-Export-Directory-Table/
- https://www.exploit-db.com/docs/english/18576-deep-dive-into-os-internals-with-windbg.pdf
- https://docs.microsoft.com/en-us/archive/msdn-magazine/2002/march/inside-windows-an-in-depth-look-into-the-win32-portable-executable-file-format-part-2

PD: 

The code will be published in https://github.com/waawaa/Exploiting-TIPS/






