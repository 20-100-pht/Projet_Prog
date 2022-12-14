#include <stdio.h>
#include <string.h>
#include <elf.h>

// Prend un fichier objet en argument et affiche son header

#if defined(__LP64__) // Permet de determiner l'architecture de notre machine 
#define ElfW(type) Elf64_ ## type // 64 bits
#else
#define ElfW(type) Elf32_ ## type
#endif

void read_elf_header(const char* elfFile) {

  ElfW(Ehdr) header;

  FILE* file = fopen(elfFile, "rb");
  if(file) {

    fread(&header, sizeof(header), 1, file);

    if (memcmp(header.e_ident, ELFMAG, SELFMAG) == 0) {
    }

    printf("ELF Header:\n");
    printf("  Magic:   ");
    for(int i = 0; i < 16; i++){
      if(header.e_ident[i] < 10) printf("0%x ", header.e_ident[i]);
      else printf("%x ", header.e_ident[i]);
    }
    printf("\n  Class:                             ??\n");
    printf("  Data:                              ??\n");
    printf("  Version:                           %d (current)\n",header.e_version);
    printf("  OS/ABI:                            ??\n");
    printf("  ABI Version:                       ??\n");
    printf("  Type:                              %d\n",header.e_type);
    printf("  Machine:                           %d\n",header.e_machine);
    printf("  Version:                           0x%d\n",header.e_version);
    printf("  Entry point address:               0x%ld\n",header.e_entry);
    printf("  Start of program headers:          %ld (bytes into file)\n",header.e_phoff);
    printf("  Start of section headers:          %ld (bytes into file)\n",header.e_shoff);
    printf("  Flags:                             0x%d\n",header.e_flags);
    printf("  Size of this header:               %d (bytes)\n",header.e_ehsize);
    printf("  Size of program headers:           %d (bytes)\n",header.e_phentsize);
    printf("  Number of program headers:         %d\n",header.e_phnum);
    printf("  Size of section headers:           %d (bytes)\n",header.e_shentsize);
    printf("  Number of section headers:         %d\n",header.e_shnum);
    printf("  Section header string table index: %d\n",header.e_shstrndx);

    fclose(file);
  }
}

int main(int argc, char *argv[]){
  if(argc != 2) printf("Erreur il manque des arguments")}

  read_elf_header(argv[1]);

  return 0;
}
