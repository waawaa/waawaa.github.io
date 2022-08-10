---
title: "[Windows Internals] Bypass Protected Process Light / ObRegisterCallbacks using Process Explorer"
header:
  teaser: "https://farm5.staticflickr.com/4076/4940499208_b79b77fb0a_z.jpg"
categories: 
  - EN
tags:
  - EN
  - Red Team
  - Malware
  - Hooking
  - Research
  - Windows Internals
author: Alejandro Pinna
---

Hi everyone! After the receival of the AMSI article, i decided to come back with more.
Today we are going to talk a little bit about PPL and a possible bypass, that requires admin privileges, but not for that less interesting.
Also we will be talking about a technique implemented to detect LSASS access in kernel side, and how process explorer can be used to bypass it.


## PPL Processes

Back in Windows Vista era, Microsoft introduced a protection for critical system processes called Protected Process (a.k.a PP), later in the Windows 8.1 era, Micro$oft introduced a new protection, very similar to PP, called Protected Process Light (a.k.a PPL), this last permits for example an antimalware service to protect itself, blocking termination attempts usually done by malicius software.

I won't go into details about PPL and PP, because there are fantastic posts talking about this, here is a must read:

- <https://itm4n.github.io/lsass-runasppl/>
- <https://itm4n.github.io/the-end-of-ppldump/>

Following there is a table with all the possible protections implemented with PP and PPL.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_07_29_PPL/PPL.png)

The protection applied to a process is specified in the _EPROCESS structure, which is an opaque kernel-side structure.

During some years, the tool PPLDump could be used to bypass this protection, but in the last months, Microsoft patched the technique exploited by this vulnerability (discovered by Alex Ionescu and James Forshaw), and in up-to-date systems the era of PPLDump is over, if you want more details about that, you can go to the post i mentioned before (it's a must read).


## Searching for a bypass

First of all, a disclaimer, i'm not going to present here a vulnerability in PPL implementation, neither any kind of vulnerability, actually i'm going to present a way to abuse some features in existing drivers to get a handle to protected process and later perform operations with that handle.

When we open process explorer with admin privileges, we see it's showing us a list with all the protected processes of the system (use process explorer colors, and you will see how your life is better).

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_07_29_PPL/Process_Explorer_PPL.png)

The first i thought when i saw this, was that process explorer was reading the protection from PEB, that has some properties indicating if a process is protected, and in case it is, if it's a PPL process.

```c
0: kd> dt _PEB 0x00000097`9dade000
win32k!_PEB
   +0x000 InheritedAddressSpace : 0 ''
   +0x001 ReadImageFileExecOptions : 0 ''
   +0x002 BeingDebugged    : 0 ''
   +0x003 BitField         : 0x46 'F'
   +0x003 ImageUsesLargePages : 0y0
   +0x003 IsProtectedProcess : 0y1
   +0x003 IsImageDynamicallyRelocated : 0y1
   +0x003 SkipPatchingUser32Forwarders : 0y0
   +0x003 IsPackagedProcess : 0y0
   +0x003 IsAppContainer   : 0y0
   +0x003 IsProtectedProcessLight : 0y1
```

But obviously, if it's a PP/PPL process, Process Explorer couldn't read the PEB of the process even running as an administrator, we can probe it with WINDBG as adminstrator and trying to attach to a PPL process.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_07_29_PPL/csrss_attach.png)

So, Process Explorer may be doing it in another way.

After searching a little bit, i found that Process Explorer was deploying a driver, called PROCEXP152, so this looks promising.

```c
lkd> lm m procexp152
Browse full module list
start             end                 module name
fffff807`52740000 fffff807`5274c000   PROCEXP152   (no symbols)       
```

This driver must be doing black magic to send the Process Explorer GUI the information about PPL processes, and there is something else, Process Explorer can kill handles even from PPL processes, so this is being obviously done from the driver.

References about killing EDRs with handles can be found in the following git repo, credits to Yaxser @Yas_o_h (i had the bad fortune to reverse engineer the Process Explorer driver before finding that repo...)

<https://github.com/Yaxser/Backstab/>

But, let's go back to the PPL part, as we said before, the Process Explorer gui is able of seeing information from Process Explorer processes, so it's getting that information from the Process Explorer driver.
In case we can contact with that driver and ask it to get a handle to a PPL process, we could use this handle as if it would be ours, so let's open PROCEXP152.sys in IDA and start reversing.

The first that must be said, is that process comunicate with drivers using device objects, those devices can be seen with WinObj tool, and usually are created using the APIs **IoCreateDevice** and **IoCreateSymbolicLink**

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_07_29_PPL/IoCreateSymbolicLink.png)

We can observe, how in Driver Entry, exists a call to IoCreateSymbolicLink, that is going to register the device object of **PROCEXP152.sys** usually, this devices have a callback that will process the input data we are sending to it.

This callback registration can be observed in the next assembly lines, where we see how a function pointer is being passed to the rax register using the following instructions:

```c
call    cs:IoCreateSymbolicLink
mov     ebx, eax
lea     rax, Callback   ; Callback
```

Digging in this callback, we find some call instructions, one of them having lot of arguments, could be the function in charge of process requests done via DeviceIoControl.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_07_29_PPL/DeviceIoControl_function.png)


## Reversing Processing Function and Structures

Inside the function, that we renamed as DeviceIoControl, we can see a switch ... case code pattern.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_07_29_PPL/switch_case.png)

And if we follow the code flow, we find that in case 0x3C, the driver will get a handle to the process ID specified via lpInBuffer and return it with the parameter specified by lpOutBuffer.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_07_29_PPL/ZwOpenProcess.png)

To see it more clear, we add the definition of DeviceIoControl.

```c
BOOL DeviceIoControl(
  [in]                HANDLE       hDevice, //HANDLE to the Device
  [in]                DWORD        dwIoControlCode, //IOCTL code
  [in, optional]      LPVOID       lpInBuffer, //In this case, process ID
  [in]                DWORD        nInBufferSize, //8 bytes
  [out, optional]     LPVOID       lpOutBuffer, //In this case, a pointer to a DWORD (LPDWORD)
  [in]                DWORD        nOutBufferSize, (8 bytes)
  [out, optional]     LPDWORD      lpBytesReturned, //Bytes returned
  [in, out, optional] LPOVERLAPPED lpOverlapped //Overlapped (nullptr)
);
```

To know how to pass the IOCTL code (0x3C), we used WinDBG, debugging the driver PROCEXP152, while the procexp tool is active, and seeing what kind of values are being passed to the callback function as IOCTL values.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_07_29_PPL/passed_value_IOCTL.png)

Once the DeviceIoControl returns, we would have a PROCESS_ALL_ACCESS handle to the PPL protected process.

This is not only useful for PPL Processes, but it's also useful when we have drivers that protect process from being opened with ObRegisterCallback, such as for example those EDRs that use callbacks for blocking user-processes that try to open a handle to LSASS.exe.

As this handle is obtained from kernel mode, that kind of protections can also be circunvented.



The Process Explorer driver, has other interesting functionalities, that are covered in the github code published with this post, such as for example killing PPL processes.

As we can see, in case 0x4, exists a function that we renamed as Close_Handle, this function expects an input with size of 32 bytes and doesn´t expect a buffer for output purposes.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_07_29_PPL/close_handle.png)

This function is really expecting an structure, that can be seen via reversing the function.

This structure is the first parameter passed to the close_handle function, so in x64 conventions, this is passed via RCX register (i hate x64 calling convention).

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_07_29_PPL/first_snippet_code.png)

In this code snippet we can see how the rcx register, that holds a pointer to the input structure is being passed to the rbx register, and later, the first position of the structure is being passed to the ebx register, that is going to be used as the first argument of PsLookProcessByProcessId (returns a the _EPROCESS structure from a process Id)

The second place where this structure is used is in the following snippet code:

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_07_29_PPL/second_snippet_code.png)

We see how rbx+18 is being passed to rcx (first argument of ObReferenceObjectByHandle), this function checks the access validation of a handle passed to that function, and if access can be granted, then returns a pointer to the object's body.

The definition of the function is as follows:

```c
NTSTATUS ObReferenceObjectByHandle(
  [in]            HANDLE                     Handle,
  [in]            ACCESS_MASK                DesiredAccess,
  [in, optional]  POBJECT_TYPE               ObjectType,
  [in]            KPROCESSOR_MODE            AccessMode,
  [out]           PVOID                      *Object,
  [out, optional] POBJECT_HANDLE_INFORMATION HandleInformation
);
```

As we can see, the first argument is a handle, so the now we know our structure must be as follows.

```c
struct structure_to_close_handle {
	DWORD processId;
	DWORD unknown;
	DWORD unkown;
	HANDLE processHandle;
};
```

We need to know what the other fields of the structure are, because for now we only know two of the four fields.

Following the code, we can follow the other places where this structure is going to be used:

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_07_29_PPL/third_code_snippet.png)

We can see a code snippet that is comparing the values of rbx+8 (second field of our structure) and the value of rsp+78h, that holds a pointer to the objects body, and in case those values are not the same, the jump will be taken, and an error will be returned, so we know that the second position of the structure has to be a pointer to the object, that can be retreived via NtQuerySystemInformation.

In this case, we didn´t find what the second field of the structure is, it probably is used in other place of the callback function.

The structure must look as follows.

```c
struct structure_to_close_handle {
	DWORD processId;
	PVOID Object;
	DWORD unknown;
	HANDLE proocessHandle;
};
```

Passing then the following data to the DeviceIoControl function, we can close handles of a PPL process, killing the process in the bast majority of the cases.

```c
DeviceIoControl(hDevice, 0x83350004, &struture_to_close_handle, sizeof(structure_to_close_handle), nullptr, NULL, &lpBytesReturned, nullptr);
```

## Conclusion

As we can see, even non vulnerable / non malicius drivers can be abused to bypass some defense mechanisms, such as PPL or EDRs protected processes.

In this case we did a bit of reverse engineering of ProcEXP driver, but probably other drivers have interesting features that can also be exploited to perform malicius actions.

Thank you for Yaxser for the code published in his repo, where we can find another implementation of this techinque.

Code is published here:

<https://github.com/waawaa/breakcyserver>

References:

- <https://itm4n.github.io/lsass-runasppl/>
- <https://itm4n.github.io/the-end-of-ppldump/>
- <https://repnz.github.io/posts/abusing-signed-drivers/>

PS: The custom MiniDumpWriteDumpA implementation has some issues and sometimes fails, but i didn´t look forward the reason, it's just a POC, if anyone knows a good MiniDumpWriteDump implementation let me know and i include it in the project.







