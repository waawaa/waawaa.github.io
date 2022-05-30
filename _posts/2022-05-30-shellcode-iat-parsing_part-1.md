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

In this, my first post after a long long time, we will be reviewing different structures of PE files, those in charge of specify which functions must be imported by a windows PE file, and also those in charge of functions exported by a DLL.

It all started during my EXP-301 training, during one of the modules, custom shellcode development is explained, based on the use of EAT of DLLs to look for useful functions, and later use that functions to load other DLLs and functions that will be used to perform further actions.

A very usual approach would be the following.

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

As we explained before you need to follow the following steps:

- The first you need to loop on the AddressOfNames array, until you locate the index of GetProcAddress string.
- The second you will use that index to locate the ordinal of the function, this ordinal will point to the real address of the function, which is stored as a relative address in the AddressOfFunctions.
- Finally, using the ordinal, the real address of the function is extracted from AddressOfFunctions.

Some posts explain very deeply this process, for example this one:

<https://xen0vas.github.io/Win32-Reverse-Shell-Shellcode-part-2-Locate-the-Export-Directory-Table>

During practicing this technique, an idea came to my mind, why not use IAT of the exe exploited, instead of using the EAT of the Kernel32 / Kernelbase DLL ??



## Explanation

First of all, must be explained that almost all the process running in a Windows OS have a kernel32 / kernelbase DLL image loaded in memory, and import functions from those DLLs, so using the IAT of the own exploited process to resolve those functions is not a fantasy.

During this post, we will be working with two structures that consist on the following.

The first one is <br>_IMAGE_IMPORT_DESCRIPTOR</br> and holds information about the name of the DLL, a pointer to the IAT, and a pointer to the names of the functions imported.

This is the definition

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

And the second structure is the own IAT (<br>_IMAGE_IMPORT_BY_NAME</br>), that as we will see during this post is different when the PE image is loaded in memory and when we inspect it in the disk.

In disk it has the following definition:

```c 
typedef struct _IMAGE_IMPORT_BY_NAME {
   USHORT Hint;
   UCHAR Name[1];
 } IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;
```

_IMAGE_IMPORT_BY_NAME is usually known as the IAT.

## Debugging those structures with Windbg and with X32DBG

All the work will be done with WinDBG, but for display ~~mental health~~ reasons, we will use also x32dbg to inspect memory in some ocasions.


First of all, we load our program (<br>asm_iat_parse.exe</br>) in windbg but emulating a suspended process, the first of all we will se how to calculate the address of IAT, and we will use those steps to see that in a process that has not been fully initialized yet.

To do that we use the following command <code  style="background-color: lightgrey; color:black;"><b>windbg.exe -le:ntdll.dll asm_parse_iat.exe</b></code>

This command will open asm_parse_iat.exe before RtlUserThreadStart is started, so IAT of the image is still intact.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2021_05_30-shellcode-part-1/windbg_start.png)


With this, let's proceed to look for the IAT manually using windbg.

The first we will access the <br>_TEB</br> structure, for that we use the <br>fs:[0]</br> register.

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
So we need to read the content of <br>fs:[0x30]</br> to access to ProcessEnvironmentBlock structure


![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_05_30-shellcode-part-1/windbg_get_peb.png)

After that, having the base address of the image, we will parse <br>_IMAGE_DOS_HEADER</br>
But before going on, let's keep the address of the ImageBase in a temporary register of WinDBG 

```c
r @$t0 = poi(poi(fs:[0x30])+0x008)
```

This will be used later to calculate other addresses that are relative to the imageBase direction, using this we don't need to hardcode addresses and this technique is scalable to other binaries.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_05_30-shellcode-part-1/windbg_get_dos_header_from_TEB.png)

Having this, we can calculate the offset to _IMAGE_NT_HEADERS, using the position 0x30 of _IMAGE_DOS_HEADER, which stores an offset to _IMAGE_NT_HEADERS and adding that offset to our temporary register

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_05_30-shellcode-part-1/windbg_get_nt_header.png)


Once we have this pointer stored, we just need to access _IMAGE_OPTIONAL_HEADER->DirectoryEntry, to get the address of _IMAGE_OPTIONAL_HEADER we use _IMAGE_NT_HEADERS->OptionalHeader which is stored in _IMAGE_NT_HEADERS+0x030

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_05_30-shellcode-part-1/windbg_get_optional_header.png)

And to finish we just need to get the address of the DataDirectory array, which has in the position 1 (DataDirectory[1]) the address of _IMAGE_IMPORT_DESCRIPTOR.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_05_30-shellcode-part-1/windbg_get_directoryentry_header.png)



To clarify, we must say that to access _IMAGE_IMPORT_DESCRIPTOR we have to access the position 1 of DataDirectory, this array is a structure described as follows.

```c
0:000> dt _IMAGE_DATA_DIRECTORY
ntdll!_IMAGE_DATA_DIRECTORY
   +0x000 VirtualAddress   : Uint4B
   +0x004 Size             : Uint4B
```
So we have to access DataDirectory+0x8 to get the relative address of _IMAGE_IMPORT_DESCRIPTOR, and later this will be added to our temporary register (stored ImageBase) to get the structure.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_05_30-shellcode-part-1/windbg_get_import_descriptor.png)

Once we have this structure located, we can resolve the name of the DLL, which in this case is VCRUNTIME140.dll

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_05_30-shellcode-part-1/windbg_get_dllname.png)

And we can also get the address of the IAT that in this case is the same for OriginalFirstThunk and FirstThunk, that happens because the process is not fully initilizated, but once the process runs, the FirstThunk will point to function addresses and OriginalFirstThunk will point to IAT (_IMAGE_IMPORT_BY_NAME)


![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_05_30-shellcode-part-1/windbg_get_function_names.png)


Once the process is initialized this array will store the same data than now, but the FirstThunk, which is in <br>_IMAGE_IMPORT_DESCRIPTOR+0x10</br> will have the address of the functions imported, ordered in the same order than in _IMAGE_IMPORT_BY_NAME (<br>OriginalFirstThunk</br>)

We can see how those address are modified, but instead of using WinDBG, we will use x32dbg, and we will set a hardware breakpoint on write at FirstThunk addresses, so we can step by step observe how that array is overwritten with the real addresses of the functions.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_05_30-shellcode-part-1/iat_pre_breakpoint.png)

The previous image shows how the iat points to the _IMAGE_IMPORT_BY_NAME array before being overrided by the loader, and the next one shows how this looks like after the process has been initialized.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_05_30-shellcode-part-1/iat_post_breakpoint.png)

Finally, we see this address point to the <br>GetModuleFileName</br> function, that as we saw before, is the first one that is imported by the executable.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_05_30-shellcode-part-1/iat_post_breakpoint_resolved.png)




## Conclusion

We have seen how import structures (arrays) can be parsed to get the index of the function name in the array, and later use that index in the address array to get the real address of that function.

Additionally, in comparison with resolving addresses parsing EAT, this method is much more simple, because we have to iterate only over one array, and with that index we can get the real address of the function without knowing the ordinal, that saves a step in comparison with EAT parsing.

In the next part of this serie we will see how to do that in assembler level and how to pop a calc using IAT resolving instead of EAT resolving.









