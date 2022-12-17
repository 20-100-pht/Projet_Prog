#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <byteswap.h>


//Fonction pour recuperer les flags de chaque section
void get_flag(int flag, char *str_flag){
  int len = 0;
  
  //Si SHF_WRITE est contenu dans flag alors on l'ajoute
  if(flag & SHF_WRITE){
    str_flag[len]='W';
    len++;
  }
  if(flag & SHF_ALLOC){
    str_flag[len]='A';
    len++;
  }
  if(flag & SHF_EXECINSTR){
    str_flag[len]='X';
    len++;
  }
  if(flag & SHF_MERGE){
    str_flag[len]='M';
    len++;
  }
  if(flag & SHF_STRINGS){
    str_flag[len]='S';
    len++;
  }
  if(flag & SHF_INFO_LINK){
    str_flag[len]='I';
    len++;
  }
  if(flag & SHF_LINK_ORDER){
    str_flag[len]='L';
    len++;
  }
  if(flag & SHF_OS_NONCONFORMING){
    str_flag[len]='O';
    len++;
  }
  if(flag & SHF_GROUP){
    str_flag[len]='G';
    len++;
  }
  if(flag & SHF_TLS){
    str_flag[len]='T';
    len++;
  }
  if(flag & SHF_MASKOS){
    str_flag[len]='o';
    len++;
  }
  if(flag & SHF_MASKPROC){
    str_flag[len]='p';
    len++;
  }

  if(len==0){
    str_flag[0]='\0';
  }else{
    str_flag[len]='\0';
  }

}

int is32_B_E(Elf32_Ehdr header){
  if(header.e_ident[4] == 1 && header.e_ident[5] == 2 && memcmp(header.e_ident, ELFMAG, SELFMAG) == 0){
    //Fichier bon
    return 0;
  }
  return 1;
}

void swap_header(Elf32_Ehdr *header){
  header->e_version = __bswap_32(header->e_version);
  header->e_entry = __bswap_32(header->e_entry);
  header->e_phoff = __bswap_32(header->e_phoff);
  header->e_machine = __bswap_16(header->e_machine);
  header->e_type = __bswap_16(header->e_type);
  header->e_shoff = __bswap_32(header->e_shoff);
  header->e_flags = __bswap_32(header->e_flags);
  header->e_ehsize = __bswap_16(header->e_ehsize);
  header->e_phentsize = __bswap_16(header->e_phentsize);
  header->e_phnum = __bswap_16(header->e_phnum);
  header->e_shentsize = __bswap_16(header->e_shentsize);
  header->e_shnum = __bswap_16(header->e_shnum);
  header->e_shstrndx = __bswap_16(header->e_shstrndx);
}

void read_elf_section_table(Elf32_Ehdr header, Elf32_Shdr sectionTable, unsigned char *buffer) {

  long int shoff = header.e_shoff;
  int shnum = header.e_shnum;
  int shentsize = header.e_shentsize;

  int typeSection[17]={0,1,2,3,4,5,6,7,8,9,10,11,0x70000000,0x7fffffff,0x80000000,0xffffffff,0x70000003};
  char *typeSectionNom[16];
  typeSectionNom[0]="NULL            ";
  typeSectionNom[1]="PROGBITS        ";
  typeSectionNom[2]="SYMTAB          ";
  typeSectionNom[3]="STRTAB          ";
  typeSectionNom[4]="RELA            ";
  typeSectionNom[5]="HASH            ";
  typeSectionNom[6]="DYNAMIC         ";
  typeSectionNom[7]="NOTE            ";
  typeSectionNom[8]="NOBITS          ";
  typeSectionNom[9]="REL             ";
  typeSectionNom[10]="SHLIB           ";
  typeSectionNom[11]="DYNSYM          ";
  typeSectionNom[12]="LOPROC          ";
  typeSectionNom[13]="HIPROC          ";
  typeSectionNom[14]="LOUSER          ";
  typeSectionNom[15]="HIUSER          ";
  typeSectionNom[16]="ARM_ATTRIBUTES  ";

  //Trouver la section SHT_SYMTAB pour avoir l'offset qui permet de trouver
  //la table des strings
  Elf32_Shdr shstrtab_section;
  for (int i = 0; i < header.e_shnum; i++) {
    memcpy(&shstrtab_section, &buffer[header.e_shoff + i * header.e_shentsize], header.e_shentsize);
    if (shstrtab_section.sh_type == SHT_SYMTAB) {
      break;
    }
  }

  printf("There are %d section headers, starting at offset 0x%lx:\n\nSection Headers:\n  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al\n", shnum, shoff);
  for(long int i = shoff; i < shoff+(shentsize*shnum); i = i + shentsize){
    memcpy(&sectionTable, &buffer[i], shentsize);    

    if ((i-shoff)/shentsize < 10) printf("  [ %ld] ", (i-shoff)/shentsize); // indice
    else printf("  [%ld] ", (i-shoff)/shentsize);
    
    //Names
    char *section_name = &buffer[__bswap_32(shstrtab_section.sh_offset) + __bswap_32(sectionTable.sh_name)];
    printf("%-16s  ", section_name);
    
    for (int i = 0; i < 17; i++)  // Type
    {
      if(__bswap_32(sectionTable.sh_type) == typeSection[i]){
        printf("%s",typeSectionNom[i]);
      }
    }
    
    printf("%8.8x ", __bswap_32(sectionTable.sh_addr)); // Adresse
    printf("%6.6x ", __bswap_32(sectionTable.sh_offset)); // Offset
    printf("%6.6x ", __bswap_32(sectionTable.sh_size)); // Size
    printf("%2.2x ", __bswap_32(sectionTable.sh_entsize)); // EntSize
    char str_flag[10];
    get_flag(__bswap_32(sectionTable.sh_flags),str_flag);
    printf("%3s ",str_flag); // Flags
    printf("%2d ", __bswap_32(sectionTable.sh_link)); // Link
    printf("%3d ", __bswap_32(sectionTable.sh_info)); // Info
    printf("%2d\n", __bswap_32(sectionTable.sh_addralign)); // Align

  }
  printf("Key to Flags:\n  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),\n  L (link order), O (extra OS processing required), G (group), T (TLS),\n  C (compressed), x (unknown), o (OS specific), E (exclude),\n  D (mbind), y (purecode), p (processor specific)\n");
}


void read_elf_header(Elf32_Ehdr header) {

  //Liste des noms des machines, a completer si on a une machine differente
  char *nomMachine[100];
  for (int i = 0; i < 100; i++)
  {
    nomMachine[i]="Inconnu";
  }
  nomMachine[62]="Advanced Micro Devices X86-64";
  nomMachine[40]="ARM";

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
  printf("  Version:                           %x (current)\n",header.e_version);
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
  printf("  Entry point address:               0x%d\n",header.e_entry);
  printf("  Start of program headers:          %d (bytes into file)\n",header.e_phoff);
  printf("  Start of section headers:          %d (bytes into file)\n",header.e_shoff);
  printf("  Flags:                             0x%x, Version5 EABI\n",header.e_flags);
  printf("  Size of this header:               %d (bytes)\n",header.e_ehsize);
  printf("  Size of program headers:           %d (bytes)\n",header.e_phentsize);
  printf("  Number of program headers:         %d\n",header.e_phnum);
  printf("  Size of section headers:           %d (bytes)\n",header.e_shentsize);
  printf("  Number of section headers:         %d\n",header.e_shnum);
  printf("  Section header string table index: %d\n",header.e_shstrndx);
  
}

int main(int argc, char *argv[]){

  if(argc != 3) printf("Erreur il manque des arguments\n");

  FILE* file = fopen(argv[1], "rb");

  if(file) {

    fseek( file, 0, SEEK_END);
    unsigned long size = ftell(file);
    
    unsigned char buffer[size];
    fseek(file, 0, SEEK_SET);
    fread(&buffer, size, 1, file);
    fclose(file);

    Elf32_Ehdr header;
    memcpy(&header, &buffer[0], 52);
    swap_header(&header);

    if(is32_B_E(header)){
      printf("ERR_ELF_FILE : Le fichier n'est pas un fichier ELF 32bits big endian\n");
      return 1;
    }


    Elf32_Shdr section;
    if (!strcmp(argv[2], "0")) read_elf_header(header);
    if (!strcmp(argv[2], "1")) read_elf_section_table(header, section, buffer);
    return 0;

  }

  printf("Erreur lecture du fichier\n");
  return 1;
}
