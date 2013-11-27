/*
	BEER: Beer Executes Elf Relocatables
	- run Linux and possibly other ELF executables on Windows

	Copyright (c) 2013 Ben "GreaseMonkey" Russell.
	All rights reserved.

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions
	are met:
	1. Redistributions of source code must retain the above copyright
	   notice, this list of conditions and the following disclaimer.
	2. Redistributions in binary form must reproduce the above copyright
	   notice, this list of conditions and the following disclaimer in the
	   documentation and/or other materials provided with the distribution.

	THIS SOFTWARE IS PROVIDED BY ITS CONTRIBUTORS ``AS IS'' AND ANY EXPRESS
	OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
	WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
	DISCLAIMED.  IN NO EVENT SHALL THE CONTRIBUTORS BE LIABLE FOR ANY
	DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
	DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
	OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
	HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
	STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
	IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
	POSSIBILITY OF SUCH DAMAGE.
*/

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>

#include <windows.h>

#include "exec_elf.h"

DWORD protflags[8] = {
	PAGE_NOACCESS,
	PAGE_READONLY,
	PAGE_READWRITE, // should be "write only" but Windows doesn't support that
	PAGE_READWRITE,
	PAGE_EXECUTE,
	PAGE_EXECUTE_READ,
	PAGE_EXECUTE_READWRITE, // should be "execute write only" but Windows doesn't support that
	PAGE_EXECUTE_READWRITE,
};

void stub(void **hack)
{
	printf("stub called from %p\n", hack[-1]);
	fflush(stdout);
	abort();
}

Elf32_Ehdr *load_elf_fp(FILE *fp)
{
	Elf32_Ehdr *ret = NULL;
	Elf32_Ehdr hdr;
	Elf32_Dyn *dyn = NULL;
	void *v_init = NULL;
	void *v_fini = NULL;
	int dyn_ents = 0;
	int i, j;

	const int mempad = (1<<16);

	hdr.e_ident[EI_MAG3] = '\x00';
	fread(&hdr, 1, sizeof(Elf32_Ehdr), fp);

	if(memcmp(hdr.e_ident, "\177ELF\001\001\001", 7))
	{
		printf("load_elf_fp: not a 32-bit LE v1 ELF file");
		return NULL;
	}

	printf("ABI: %i version = %i\n"
		, hdr.e_ident[EI_OSABI]
		, hdr.e_ident[EI_ABIVERSION]);
	printf("File type: %i\n", hdr.e_type);
	printf("Machine: %i\n", hdr.e_machine);
	printf("Version: %i\n", hdr.e_version);
	printf("Entry point: 0x%08X\n", hdr.e_entry);
	printf("Flags: 0x%08X\n", hdr.e_flags);
	printf("String table index: %i\n", hdr.e_shstrndx);

	if(hdr.e_type != ET_EXEC)
	{
		printf("load_elf_fp: not an executable ELF\n");
		return NULL;
	}

	if(hdr.e_machine != EM_386 && hdr.e_machine != EM_486)
	{
		// For reference, EM_X86_64 is for amd64
		printf("load_elf_fp: not an Intel 386/486 ELF\n");
		return NULL;
	}

	if(hdr.e_version != EV_CURRENT)
	{
		printf("load_elf_fp: unsupported ELF version\n");
		return NULL;
	}

	if(hdr.e_phentsize != sizeof(Elf32_Phdr))
	{
		printf("load_elf_fp: invalid program header entry size\n");
		return NULL;
	}

	// Load program headers
	Elf32_Phdr *ph = malloc(sizeof(Elf32_Phdr) * hdr.e_phnum);
	fseek(fp, hdr.e_phoff, SEEK_SET);
	fread(ph, 1, hdr.e_phnum * sizeof(Elf32_Phdr), fp);

	printf("Program headers:\n");
	for(i = 0; i < hdr.e_phnum; i++)
	{
		printf("- Program header %3i, type %08X, virt %08X, file %08X, fsize %08X, "
			"msize %08X, align %08X, flags %08X\n",
			i, ph[i].p_type,
			ph[i].p_vaddr, ph[i].p_offset,
			ph[i].p_filesz, ph[i].p_memsz,
			ph[i].p_align, ph[i].p_flags);
		switch(ph[i].p_type)
		{
			case PT_DYNAMIC:
				dyn = (Elf32_Dyn *)(ph[i].p_vaddr);
				dyn_ents = ph[i].p_memsz / sizeof(Elf32_Dyn);
				break;
		}
	}

	// Merge the pages because ELF page granularity is shit
	// TODO: sort out permissions properly (which will require a better algo)
	Elf32_Phdr *ch = malloc(hdr.e_phnum * sizeof(Elf32_Phdr));
	memcpy(ch, ph, hdr.e_phnum * sizeof(Elf32_Phdr));

	// pad them first
	for(i = 0; i < hdr.e_phnum; i++)
	{
		//
		Elf32_Addr a0s = ch[i].p_vaddr;
		Elf32_Addr a0e = a0s + ch[i].p_memsz;
		a0s &= ~(mempad-1);
		a0e +=  (mempad-1);
		a0e &= ~(mempad-1);
		ch[i].p_vaddr = a0s;
		ch[i].p_memsz = a0e - a0s;
	}

	// now merge
	for(i = 0; i < hdr.e_phnum; i++)
	if(ch[i].p_type != PT_NULL)
	{
		Elf32_Addr a0s = ch[i].p_vaddr;
		Elf32_Addr a0e = a0s + ch[i].p_memsz;

		// merge
		for(j = 1; j < hdr.e_phnum; j++)
		{
			Elf32_Addr a1s = ch[j].p_vaddr;
			Elf32_Addr a1e = a1s + ch[j].p_memsz;

			// Check ordering
			if(a0s <= a1s)
			{
				// a0s static
				if(a0e <= a1s)
				{
					// a0 before a1 no overlap
					continue;
				} else if(a0e < a1e){
					// a0e before a1e
					a0e = a1e;
				} else {
					// a1 fully enclosed in a0
					// still nuke a1
				}
			} else if(a0e < a1e) {
				// a0s before a1e
				a0s = a1s;
			} else {
				// a1 before a0 no overlap
				continue;
			}

			ch[i].p_flags |= ch[j].p_flags;
			ch[j].p_type = PT_NULL;
		}

		// allocate
		Elf32_Addr addr = (ch[i].p_vaddr = a0s);
		Elf32_Word size = (ch[i].p_memsz = a0e - a0s);
		
		printf("alloc %2i %08X len %08X\n", i, addr, size);
		void *agot = VirtualAlloc((void *)addr, size,
			MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		printf("- expected %p, got %p\n", addr, agot);
	}

	// Write the required data to memory
	for(i = 0; i < hdr.e_phnum; i++)
	{
		if(ph[i].p_filesz > 0)
		{
			if(ph[i].p_offset == 0)
			{
				printf("ELF header found\n");
				ret = (Elf32_Ehdr *)(ph[i].p_vaddr);
			}

			printf("commit %08X size %08X offs %08X\n",
				ph[i].p_vaddr, ph[i].p_filesz, ph[i].p_offset);
			fseek(fp, ph[i].p_offset, SEEK_SET);
			fread((void *)(ph[i].p_vaddr), 1, ph[i].p_filesz, fp);
		}
	}

	// Find mandatory values in .dynamic
	printf("Dynamic linking info (%i entries):\n", dyn_ents);
	const char *dynstr = NULL;
	Elf32_Sym *dynsym = NULL;
	Elf32_Rel *rel = NULL;
	Elf32_Rel *jmprel = NULL;
	Elf32_Addr *pltgot = NULL;
	int relents = 0;

	for(i = 0; i < dyn_ents; i++)
	switch(dyn[i].d_tag)
	{
		case DT_STRTAB:
			dynstr = (const char *)(dyn[i].d_un.d_ptr);
			break;
		case DT_SYMTAB:
			dynsym = (Elf32_Sym *)(dyn[i].d_un.d_ptr);
			break;
		case DT_RELSZ:
			relents = dyn[i].d_un.d_val/sizeof(Elf32_Rel);
			break;
		case DT_REL:
			rel = (Elf32_Rel *)(dyn[i].d_un.d_ptr);
			break;
		case DT_JMPREL:
			jmprel = (Elf32_Rel *)(dyn[i].d_un.d_ptr);
			break;
		case DT_PLTGOT:
			pltgot = (Elf32_Addr *)(dyn[i].d_un.d_ptr);
			break;
		case DT_INIT:
			v_init = (void *)(dyn[i].d_un.d_ptr);
			break;
		case DT_FINI:
			v_fini = (void *)(dyn[i].d_un.d_ptr);
			break;
	}

	for(i = 0; i < dyn_ents; i++)
	{
		printf("- %3i: %08X %08X\n", i, dyn[i].d_tag, dyn[i].d_un.d_val);
		if(dyn[i].d_tag == DT_NULL)
			break;

		switch(dyn[i].d_tag)
		{
			case DT_NEEDED: printf("\t- DT_NEEDED [%s]\n", dynstr + dyn[i].d_un.d_val); break;
			case DT_PLTRELSZ: printf("\t- DT_PLTRELSZ %i\n", dyn[i].d_un.d_val); break;
			case DT_PLTGOT: printf("\t- DT_PLTGOT 0x%08X\n", dyn[i].d_un.d_val); break;
			case DT_HASH: printf("\t- DT_HASH 0x%08X\n", dyn[i].d_un.d_ptr); break;
			case DT_STRTAB: printf("\t- DT_STRTAB 0x%08X\n", dyn[i].d_un.d_ptr); break;
			case DT_SYMTAB: printf("\t- DT_SYMTAB 0x%08X\n", dyn[i].d_un.d_ptr); break;
			case DT_RELA: printf("\t- DT_RELA 0x%08X\n", dyn[i].d_un.d_ptr); break;
			case DT_RELASZ: printf("\t- DT_RELASZ %i\n", dyn[i].d_un.d_val); break;
			case DT_RELAENT: printf("\t- DT_RELAENT %i\n", dyn[i].d_un.d_val); break;
			case DT_STRSZ: printf("\t- DT_STRSZ %i\n", dyn[i].d_un.d_val); break;
			case DT_SYMENT: printf("\t- DT_SYMENT %i\n", dyn[i].d_un.d_val); break;
			case DT_INIT: printf("\t- DT_INIT 0x%08X\n", dyn[i].d_un.d_ptr); break;
			case DT_FINI: printf("\t- DT_FINI 0x%08X\n", dyn[i].d_un.d_ptr); break;
			case DT_SONAME: printf("\t- DT_SONAME [%s]\n", dynstr + dyn[i].d_un.d_val); break;
			case DT_RPATH: printf("\t- DT_RPATH [%s]\n", dynstr + dyn[i].d_un.d_val); break;
			case DT_SYMBOLIC: printf("\t- DT_SYMBOLIC\n"); break;
			case DT_REL: printf("\t- DT_REL 0x%08X\n", dyn[i].d_un.d_ptr); break;
			case DT_RELSZ: printf("\t- DT_RELSZ %i\n", dyn[i].d_un.d_val); break;
			case DT_RELENT: printf("\t- DT_RELENT %i\n", dyn[i].d_un.d_val); break;
			case DT_PLTREL:
				printf("\t- DT_PLTREL 0x%08X %s\n", dyn[i].d_un.d_val,
					dyn[i].d_un.d_val == DT_RELA ? "DT_RELA"
					: dyn[i].d_un.d_val == DT_REL ? "DT_REL"
					: "?");
				break;
			case DT_DEBUG: printf("\t- DT_DEBUG 0x%08X\n", dyn[i].d_un.d_ptr); break;
			case DT_TEXTREL: printf("\t- DT_TEXTREL\n"); break;
			case DT_JMPREL: printf("\t- DT_JMPREL 0x%08X\n", dyn[i].d_un.d_ptr); break;
			case DT_BIND_NOW: printf("\t- DT_BIND_NOW\n"); break;
		}
	}

	printf("Relocations (%i entries):\n", relents);
	for(i = 0; i < relents; i++)
	{
		//
		printf("- %5i: offs %08X, info %08X, val %08X\n", i,
			jmprel[i].r_offset, jmprel[i].r_info,
			*(uint32_t *)(jmprel[i].r_offset));
	}

	// attempt to run .init
	if(v_init != NULL)
	{
		printf("Running .init\n");
		printf("Entry point: 0x%p\n", v_init);
		((void (*)(void))v_init)();
		printf("MIRACLE: It didn't crash!\n");
	}

	// attempt to run entry point
	printf("Running ELF\n");
	void *ent = (void *)(hdr.e_entry);
	printf("Entry point: 0x%p\n", ent);
	((void (*)(void))ent)();
	printf("MIRACLE: It didn't crash!\n");

	// attempt to run .fini
	if(v_fini != NULL)
	{
		printf("Running .fini\n");
		printf("Entry point: 0x%p\n", v_fini);
		((void (*)(void))v_fini)();
		printf("MIRACLE: It didn't crash!\n");
	}

	// clean up
	free(ph); free(ch);
	return ret;
}

Elf32_Ehdr *load_elf_fname(const char *fname)
{
	FILE *fp = fopen(fname, "rb");

	Elf32_Ehdr *ret = load_elf_fp(fp);
	fclose(fp);

	return ret;
}

int main(int argc, char *argv[])
{
	Elf32_Ehdr *elf = load_elf_fname(argv[1]);

	if(elf == NULL)
		return 1;
	

	return 0;
}

