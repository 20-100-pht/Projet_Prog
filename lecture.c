#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>

// Prend un fichier objet en argument et affiche son header

#if defined(__LP64__) // Permet de determiner l'architecture de notre machine 
#define ElfW(type) Elf64_ ## type // 64 bits
#else
#define ElfW(type) Elf32_ ## type
#endif

void read_elf_section_table(const char* elfFile) {

  ElfW(Ehdr) header;
  Elf32_Shdr sectionTable;

  FILE* file = fopen(elfFile, "rb");
  if(file) {

    fseek( file, 0, SEEK_END);
    unsigned long size = ftell(file);
    
    unsigned char buffer[size];
    fseek(file, 0, SEEK_SET);
    fread(&buffer, size, 1, file);
    fclose(file);

    memcpy(&header, &buffer[0], 64);
  
    long int shoff = header.e_shoff;
    int shnum = header.e_shnum;
    int shentsize = header.e_shentsize;

    int typeSection[16]={0,1,2,3,4,5,6,7,8,9,10,11,0x70000000,0x7fffffff,0x80000000,0xffffffff};
    char *typeSectionNom[16];
    typeSectionNom[0]="SHT_NULL        ";
    typeSectionNom[1]="SHT_PROGBITS    ";
    typeSectionNom[2]="SHT_SYMTAB      ";
    typeSectionNom[3]="SHT_STRTAB      ";
    typeSectionNom[4]="SHT_RELA        ";
    typeSectionNom[5]="SHT_HASH        ";
    typeSectionNom[6]="SHT_DYNAMIC     ";
    typeSectionNom[7]="SHT_NOTE        ";
    typeSectionNom[8]="SHT_NOBITS      ";
    typeSectionNom[9]="SHT_REL         ";
    typeSectionNom[10]="SHT_SHLIB       ";
    typeSectionNom[11]="SHT_DYNSYM      ";
    typeSectionNom[12]="SHT_LOPROC      ";
    typeSectionNom[14]="SHT_HIPROC      ";
    typeSectionNom[15]="SHT_LOUSER      ";
    typeSectionNom[16]="SHT_HIUSER      ";
    
    printf("There are %d section headers, starting at offset 0x%lx:\n\nSection Headers:\n  [Nr] Name              Type             Address           Offset\n       Size              EntSize          Flags  Link  Info  Align\n", shnum, shoff);
    for(long int i = shoff; i < shoff+(shentsize*shnum); i = i + shentsize){
      memcpy(&sectionTable, &buffer[i], shentsize);

      if ((i-shoff)/shentsize < 10) printf("  [ %ld] ", (i-shoff)/shentsize); // indice
      else printf("  [%ld] ", (i-shoff)/shentsize);

      printf("????????????????  "); // Name
      for (int i = 0; i < 9; i++)  // Type
      {
        if(sectionTable.sh_type == typeSection[i]){
          printf("%s ",typeSectionNom[i]);
        }
      }
      printf("????????????????  "); // Adresse
      printf( "0x%08.8X         type-> %d     offset -> %d\n", sectionTable.sh_offset,sectionTable.sh_type, sectionTable.sh_offset); // Offset
      printf("       %016.16d  ", sectionTable.sh_size); // Size
      printf("%016.16d ", sectionTable.sh_entsize); // EntSize
      printf(" ?        "); // Flags
      printf("?     "); // Link
      printf("?     "); // Info
      printf("?   \n"); // Align
      
             
    }
    printf("Key to Flags:\n  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),\n  L (link order), O (extra OS processing required), G (group), T (TLS),\n  C (compressed), x (unknown), o (OS specific), E (exclude),\n  D (mbind), l (large), p (processor specific)\n");
  }
}


void read_elf_header(const char* elfFile) {

  ElfW(Ehdr) header;

  FILE* file = fopen(elfFile, "rb");
  if(file) {

    fread(&header, sizeof(header), 1, file);

    if (memcmp(header.e_ident, ELFMAG, SELFMAG) != 0) {
      printf("ERR_ELF_FILE : Le fichier donné n'est pas un fichier ELF.");
      exit(0);
    }

    //Liste des noms des machines, a completer si on a une machine differente
    char *nomMachine[100];
    for (int i = 0; i < 100; i++)
    {
      nomMachine[i]="Inconnu";
    }
    nomMachine[62]="Advanced Micro Devices X86-64";

    //Liste des noms de type de fichiers
    int typeFichier[9]={0,1,2,3,4,0xfe00,0xfeff,0xff00,0xffff};
    char *typeFichierNom[9];
    typeFichierNom[0]="No file type";
    typeFichierNom[1]="REL (Relocatable file)";
    typeFichierNom[2]="EXEC (Executable file)";
    typeFichierNom[3]="DYN (Position-Independent Executable file)";
    typeFichierNom[4]="CORE (Core file)";
    typeFichierNom[5]="LOOS (Operating system-specific)";
    typeFichierNom[6]="HIOS (Operating system-specific)";
    typeFichierNom[7]="LOPR (Processor-specific)";
    typeFichierNom[8]="HIPR (Processor-specific)";

    //Liste des OS ou extensions ELF specifique aux ABI
    char *nomOSABI[15];
    for (int i = 0; i < 15; i++)
    {
      nomOSABI[i]="Inconnu";
    }
    nomOSABI[0]="UNIX - System V";

    //Liste des type de data
    char *nomData[3];
    nomData[0]="Invalid data encoding";
    nomData[1]="2's complement, little endian";
    nomData[2]="2's complement, big endian";

    //Liste des noms de classe
    char *nomClasse[3];
    nomClasse[0]="Invalid class";
    nomClasse[1]="ELF32";
    nomClasse[2]="ELF64";


    printf("ELF Header:\n");
    printf("  Magic:   ");
    for(int i = 0; i < 16; i++){
      if(header.e_ident[i] < 10) printf("0%x ", header.e_ident[i]);
      else printf("%x ", header.e_ident[i]);
    }
    printf("\n  Class:                             %s\n",nomClasse[header.e_ident[4]]);
    printf("  Data:                              %s\n",nomData[header.e_ident[5]]);
    printf("  Version:                           %d (current)\n",header.e_version);
    printf("  OS/ABI:                            %s\n",nomOSABI[header.e_ident[7]]);
    printf("  ABI Version:                       %d\n",header.e_ident[8]);
    for (int i = 0; i < 9; i++)
    {
      if(header.e_type == typeFichier[i]){
        printf("  Type:                              %s\n",typeFichierNom[i]);
      }
    }
    printf("  Machine:                           %s\n",nomMachine[header.e_machine]);
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
  if(argc != 3) printf("Erreur il manque des arguments");

  if (!strcmp(argv[2], "0")) read_elf_header(argv[1]);
  if (!strcmp(argv[2], "1")) read_elf_section_table(argv[1]);

  return 0;
}
