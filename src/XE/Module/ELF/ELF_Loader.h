#ifndef ELFLOAD_H
#define ELFLOAD_H


#include "XE/XE.h"

#include <sys/types.h>

#include "elfnative.h"


#define MAX_ELF_FILES 255




#define HOSTLIB_NOT  0
#define HOSTLIB_HOST 1
#define HOSTLIB_DL   2

/* Basic structure for ELF files mid-load */
typedef struct ELF_File {
    char *nm;

    /* if this is actually a host library, this is set to 1 */
    char hostlib;

    /* the complete program, in memory */
    void *prog;
    size_t proglen;

    /* same pointer, actually */
    ElfNative_Ehdr *ehdr;

    /* the size in memory of this file */
    ssize_t memsz;

    /* the minimum and maximum position of the loaded file, ideally */
    void* min, *max;

    /* the actual location where this file was loaded */
    void *loc;

    /* the offset of this file's real loaded location from its internal location */
    ssize_t offset;

    /* the dynamic entries table */
    ElfNative_Dyn *dynamic;

    /* the string table */
    char *strtab;

    /* and symbol table */
    ElfNative_Sym *symtab;

    /* with its associated hash table */
    ElfNative_Word *hashtab;
#define ELFFILE_NBUCKET(f) ((f)->hashtab[0])
#define ELFFILE_NCHAIN(f) ((f)->hashtab[1])
#define ELFFILE_BUCKET(f, i) ((f)->hashtab[(i) + 2])
#define ELFFILE_CHAIN(f, i) ((f)->hashtab[(i) + ELFFILE_NBUCKET(f) + 2])

    /* relocation table(s) */
    ElfNative_Rel *rel;
    size_t relsz;
    ElfNative_Rela *rela;
    size_t relasz;
    void *jmprel;
    size_t jmprelsz;
	
	void* shdr_madr_text;
}ELF_File;

extern struct ELF_File elfFiles[MAX_ELF_FILES];
extern int elfFileCount;

void relocateELFs();
void relocateELF(int fileNo, struct ELF_File *f);
void initELF(struct ELF_File *except);
void readFile(const char *nm, const char *instdir, struct ELF_File *ef);
void closeFile(struct ELF_File *ef);
void *findELFSymbol(const char *nm, struct ELF_File *onlyin, int localin, int notin,
                    ElfNative_Sym **syminto);
ElfNative_Word elf_hash(const unsigned char *name);


XE_Module* 
	Load_Module_ELF(XE_Module* _module);
ELF_File* 
	Load_Module_ELF_MEM(char *nm, void* data, size_t size);
int 
	CallEntryPoint_ELF(ELF_File* m);

#endif
