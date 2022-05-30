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
gallery:
          - url: /assets/images/2018-01-30-weblogic-cve-2017-10271/lines.png
            image_path: /assets/images/2018-01-30-weblogic-cve-2017-10271/lines.png
            alt: "Peticion Lineas"
            title: "Contador de caracteres por DNS"
          - url: /assets/images/2018-01-30-weblogic-cve-2017-10271/respuesta_dns.png
            image_path: /assets/images/2018-01-30-weblogic-cve-2017-10271/respuesta_dns.png
            alt: "Respuesta Lineas"
            title: "Respuesta al XML que exfiltra dicha información"
          - url: /assets/images/2018-01-30-weblogic-cve-2017-10271/intruder.png
            image_path: /assets/images/2018-01-30-weblogic-cve-2017-10271/intruder.png
            alt: "Respuesta Lineas"
            title: "Respuesta al XML que exfiltra dicha información"
gallery2:
          - url: /assets/images/2018-01-30-weblogic-cve-2017-10271/exfil.png
            image_path: /assets/images/2018-01-30-weblogic-cve-2017-10271/exfil.png
            alt: "Peticion Lineas"
            title: "Contador de caracteres por DNS"
          - url: /assets/images/2018-01-30-weblogic-cve-2017-10271/respuesta_dns_exfil.png
            image_path: /assets/images/2018-01-30-weblogic-cve-2017-10271/respuesta_dns_exfil.png
            alt: "Respuesta Lineas"
            title: "Respuesta al XML que exfiltra dicha información"
gallery3:
          - url: /assets/images/2018-01-30-weblogic-cve-2017-10271/shell_dns.png
            image_path: /assets/images/2018-01-30-weblogic-cve-2017-10271/shell_dns.png
            alt: "Shell DNS"
            title: "Shell DNS"
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

```
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

The first one is **_IMAGE_IMPORT_DESCRIPTOR ** and holds information about the name of the DLL, a pointer to the IAT, and a pointer to the names of the functions imported.

This is the definition

``` typedef struct _IMAGE_IMPORT_DESCRIPTOR {
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

And the second structure is the own IAT (**_IMAGE_IMPORT_BY_NAME**), that as we will see during this post is different when the PE image is loaded in memory and when we inspect it in the disk.

In disk it has the following definition:

```
 typedef struct _IMAGE_IMPORT_BY_NAME {
   USHORT Hint;
   UCHAR Name[1];
 } IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;
```

_IMAGE_IMPORT_BY_NAME is usually known as the IAT.

## Debugging those structures with Windbg and with X32DBG

All the work will be done with WinDBG, but for display ~~mental health~~ reasons, we will use also x32dbg to inspect memory in some ocasions.











