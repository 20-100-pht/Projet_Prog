#include <elf.h>

typedef struct {
  Elf32_Word sh_name;
  Elf32_Word sh_type;
  Elf32_Word sh_flags;
  Elf32_Addr sh_addr;
  Elf32_Off sh_offset;
  Elf32_Word sh_size;
  Elf32_Word sh_link;
  Elf32_Word sh_info;
  Elf32_Word sh_addralign;
  Elf32_Word sh_entsize;
  unsigned char *nameNotid;
} Elf32_Shdr_notELF;

typedef unsigned char** Elf32_Sdumps;
typedef Elf32_Shdr_notELF* Elf32_SHeaders;

typedef struct {
  Elf32_Ehdr *header;
  Elf32_Sdumps secDumps;
  Elf32_SHeaders secHeaders;
  Elf32_Sym *symbolTable;
  unsigned char **strTable;
} Elf;

Elf *read_elf(unsigned char *buffer);