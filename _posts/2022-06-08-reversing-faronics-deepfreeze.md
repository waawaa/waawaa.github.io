---
title: "[Exploiting] Reversing Faronics - Deep Freeze to locate DOS and Heap Overflows"
header:
  teaser: "https://farm5.staticflickr.com/4076/4940499208_b79b77fb0a_z.jpg"
categories: 
  - ES
tags:
  - ES
  - Red Team
  - Shellcode
  - Exploiting
  - Reversing
  - Research
  - IDA Pro
  - WinDBG
author: Alejandro Pinna
---

Hi to all!!

Again back here.

In this post we will cover how to reverse engineering Faronics - Deep Freeze (legacy) software to locate different vulnerabilities, and how to trigger this vulnerabilities to get a (till the moment) DoS in the DFServerService.

Exploiting those vulnerabilities is out of the scope of this post, and i hope we can speak about that in the subsequent publications but ~~spoiler~~ this is a Heap Overflow, and my knowledge is not so deep yet to exploit that kind of vulnerabilites.

## The application

The application we will use is Faronics Enterprise Server in version 8.38.220 which is an old one, and the majority of bugs existing in this application have been patched in the new one, although still it's possible to trigger a DoS because of reading unallocated memory, as we will see next.

This application has a client - server architecture, and is useful in case you need to preserve the state of a host without being modified, as for example in a school.

## Let's do it

Initially we will see which services runs that application and very fast the one called DFServerService.exe running in port 7725 draws our attention.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_05_30-shellcode-part-1/tcpview.png)


If we try to open the EXE with IDA Pro we will see it is packed with UPX, but we can fastly unpack it with CFF Explorer.

Next, we will open WinDBG, IDA Pro and the native client of the application, so we can see how a legit client works and what kind of data it sends.

When opening it with Ida Pro we can see quickly that it is importing **recv** function from wsock32 DLL, so let's use Cross-Reference utilities of Ida Pro to see where it is being called.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_05_30-shellcode-part-1/crossreferences.png)

While reviewing recv caller functions we see the first strange thing. When pushing arguments in the stack, it doesn't use ebp+offset to reference variables and doesn't use even an structure approach, as could be the following,

```c
mov ebx, [ebp-offset]
add ebx, 0x10
push ebx ; pushes for example buf
```

Instead it uses always the eax register, and pushes it to another function that will move eax+8 to another function that also will get eax+8 and latter with that it will reference a relative offset from that modified eax register.

PD: After digging deeper in the application, it looks like this behaviour is because the caller function of **recv** is called using CreateThread and if we see the CreateThread definition we see you can´t pass multiple arguments.

```c
HANDLE CreateThread(
  [in, optional]  LPSECURITY_ATTRIBUTES   lpThreadAttributes,
  [in]            SIZE_T                  dwStackSize,
  [in]            LPTHREAD_START_ROUTINE  lpStartAddress,
  [in, optional]  __drv_aliasesMem LPVOID lpParameter,
  [in]            DWORD                   dwCreationFlags,
  [out, optional] LPDWORD                 lpThreadId
);
```

Instead you will pass only a pointer to a structure that will hold all the parameters you need to pass to the called function.


