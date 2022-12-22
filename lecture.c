#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <byteswap.h>
#include <ctype.h>

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

void read_elf_relocation_section(Elf32_Ehdr header, Elf32_Shdr_notELF *TabSectionHeader, unsigned char *buffer) {
  Elf32_Rel *relocSect = NULL;
  int size=0;
  int offset=0;
  //On cherche la section reloc
  for (int i = 0; i < header.e_shnum; i++) {
    //Si reloc
    if (__bswap_32(TabSectionHeader[i].sh_type) == SHT_REL){
      size = __bswap_32(TabSectionHeader[i].sh_size) / sizeof(Elf32_Rel);
      relocSect = malloc(__bswap_32(TabSectionHeader[i].sh_size));
      offset=__bswap_32(TabSectionHeader[i].sh_offset);
      //Copie de la section reloc
      memcpy(relocSect, &buffer[__bswap_32(TabSectionHeader[i].sh_offset)], __bswap_32(TabSectionHeader[i].sh_size));
      break;
    };
  }

  int typeRel[8]={0x91c,0x28,0x111c,0xf02,0xe02,0x141c,0x1502,0x1602};
  char *typeRelNom[8];
  typeRelNom[0]="R_ARM_CALL        ";
  typeRelNom[1]="R_ARM_V4BX        ";
  typeRelNom[2]="R_ARM_CALL        ";
  typeRelNom[3]="R_ARM_ABS32       ";
  typeRelNom[4]="R_ARM_CALL        ";
  typeRelNom[5]="R_ARM_CALL        ";
  typeRelNom[6]="R_ARM_ABS32       ";
  typeRelNom[7]="R_ARM_ABS32       ";


  printf("\nRelocation section '.rel.text' at offset 0x%x contains %d entries:\n Offset     Info    Type            Sym.Value  Sym. Name\n",offset,size);
  for (int i = 0; i < size; i++)
  {
    printf("%8.8x  ",__bswap_32(relocSect[i].r_offset));
    printf("%8.8x ",__bswap_32(relocSect[i].r_info));
    for (int j = 0; j < 8; j++)
    {
      if(__bswap_32(relocSect[i].r_info) != typeRel[j])continue;
      printf("%s",typeRelNom[j]);
    }
    printf("%d\n",__bswap_32(relocSect[i].r_info)>>8);

    
  }
  




}

void read_elf_symbol_table(Elf32_Ehdr header, Elf32_Shdr_notELF *TabSectionHeader, unsigned char *buffer) {
  Elf32_Sym *symbolTable = NULL;
  //Pointeur vers la table str
  unsigned char *strTab;
  int size = 0;

  char *typeSectionNom[19];
  typeSectionNom[0]="NOTYPE  ";
  typeSectionNom[1]="OBJECT  ";
  typeSectionNom[2]="FUNC    ";
  typeSectionNom[3]="SECTION ";
  typeSectionNom[4]="FILE    ";
  typeSectionNom[5]="COMMON  ";
  typeSectionNom[6]="TLS     ";
  typeSectionNom[7]="LOOS    ";
  typeSectionNom[8]="HIOS    ";
  typeSectionNom[9]="LOPROC  ";
  typeSectionNom[10]="LOPROC  ";
  typeSectionNom[11]="HIPROC  ";
  typeSectionNom[16]="NOTYPE  ";
  typeSectionNom[17]="OBJECT  ";
  typeSectionNom[18]="FUNC    ";

  char *bindType[7];
  bindType[0]="LOCAL  ";
  bindType[1]="GLOBAL ";
  bindType[2]="WEAK   ";
  bindType[3]="LOOS   ";
  bindType[4]="HIOS   ";
  bindType[5]="LOPROC ";
  bindType[6]="HIPROC ";

  char *visType[7];
  visType[0]="DEFAULT  ";
  visType[1]="INTERNAL ";
  visType[2]="HIDDEN   ";
  visType[3]="PROTECTED";
  visType[4]="EXPORTED ";
  visType[5]="SINGLETON";
  visType[6]="ELIMINATE";

  int indType[9]={0,1,2,3,4,5,6,7,0xfff1};
  char *indTypeNom[9];
  indTypeNom[0]="UND ";
  indTypeNom[1]="  1 ";
  indTypeNom[2]="  2 ";
  indTypeNom[3]="  3 ";
  indTypeNom[4]="  4 ";
  indTypeNom[5]="  5 ";
  indTypeNom[6]="  6 ";
  indTypeNom[7]="  7 ";
  indTypeNom[8]="ABS ";

  //On cherche la table des symbole et de str
  for (int i = 0; i < header.e_shnum; i++) {

    //Si table des symboles
    if (__bswap_32(TabSectionHeader[i].sh_type) == SHT_SYMTAB){
      //Prendre le nombre d'entrees
      size = __bswap_32(TabSectionHeader[i].sh_size) / sizeof(Elf32_Sym);
      symbolTable = malloc(size * sizeof(Elf32_Sym));
      //Copy de la table symboles
      memcpy(symbolTable, &buffer[__bswap_32(TabSectionHeader[i].sh_offset)], size * sizeof(Elf32_Sym));
    };

    if (__bswap_32(TabSectionHeader[i].sh_type) == SHT_STRTAB){
      //adresse de la table str
      strTab = &buffer[__bswap_32(TabSectionHeader[i].sh_addr)+__bswap_32(TabSectionHeader[i].sh_offset)];
      break;
    };
  }

  printf("\nSymbol table '.symtab' contains %d entries:\n   Num:    Value  Size Type    Bind   Vis      Ndx Name\n",size);
  for (int j = 0; j < size; j++) {
    printf("   %3d: ",j); // Num
    printf("%8.8x  ", __bswap_32(symbolTable[j].st_value)); // Val
    printf("%4d ", __bswap_32(symbolTable[j].st_size)); // Size
    printf("%s", typeSectionNom[symbolTable[j].st_info]); // Type
    printf("%s", bindType[symbolTable[j].st_info >> 4]); //Bind
    printf("%s", visType[symbolTable[j].st_other]); // Vis
    int i = 0;
    //Chaque type d'index
    for (i; i < 9; i++)
    {
      if(__bswap_16(symbolTable[j].st_shndx) != indType[i]) continue;
      printf("%s", indTypeNom[i]); // Ndx
      break;
    }
    //Si type est section alors shstrtab sinon strtab
    if(symbolTable[j].st_info == 3){
      printf("%s\n", TabSectionHeader[i].nameNotid); // Name
    }else{
      printf("%s\n", strTab + __bswap_32(symbolTable[j].st_name)); //Name
    }

  }

  free(symbolTable);
}

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

void read_elf_section_dump(Elf32_Ehdr header, Elf32_Shdr_notELF *TabSectionHeader, unsigned char *buffer, int num) {
  int flag = 0;
  for (int i = 0; i < header.e_shnum; i++) {

    if(i == num){
      //Si la section n'as pas de contenu et si elle n'est pas de type : NOBITS
      if(__bswap_32(TabSectionHeader[i].sh_size) != 0 && __bswap_32(TabSectionHeader[i].sh_type) != 0x8){
        printf("\nHex dump of section '%s':\n", TabSectionHeader[i].nameNotid);

        if(i==1){ //A regler!
          printf(" NOTE: This section has relocations against it, but these have NOT been applied to this dump.\n");
        }

        char inAscii[17];
        inAscii[16]='\0';
        int affiche=0;
        unsigned char *section_data = &buffer[__bswap_32(TabSectionHeader[i].sh_addr)+__bswap_32(TabSectionHeader[i].sh_offset)];
        int max=__bswap_32(TabSectionHeader[i].sh_size);
        for (int j = 0; j < max; j++)
        {
          if(j%16==0){
            printf("  0x%08x ",j);
          }

          printf("%02hhx",section_data[j]);
          inAscii[j%16]=(isprint(section_data[j]))?section_data[j]:'.';
          inAscii[(j%16)+1]='\0';
          affiche=0;
          if((j%4)==3){
            printf(" ");
            flag ++;
          }
          if (flag == 4){
            printf("%s\n",inAscii);
            affiche=1;
            flag = 0;
          }
        }
        int n=(16-(max%16))*2;
        n+=(n%8==0)?(n/8)-1:(n/8);
        if(affiche==0){
          printf("%*c %s\n",n,' ',inAscii);
        }
        printf("\n");
      }
      else printf("Section '%s' has no data to dump.\n", TabSectionHeader[i].nameNotid);
      
    }

  }
}

void init_TabSectionHeader(Elf32_Ehdr header, Elf32_Shdr_notELF *TabSectionHeader, unsigned char *buffer){
  //Trouver la section SHT_SYMTAB pour avoir l'offset qui permet de trouver
  //la table des strings
  Elf32_Shdr shstrtab_section;
  for (int i = 0; i < header.e_shnum; i++) {
    memcpy(&shstrtab_section, &buffer[header.e_shoff + i * header.e_shentsize], header.e_shentsize);
    if (shstrtab_section.sh_type == SHT_SYMTAB) {
      break;
    }
  }

  for(long int i = header.e_shoff; i < header.e_shoff+(header.e_shentsize*header.e_shnum); i = i + header.e_shentsize){
    long int j = (i-header.e_shoff)/header.e_shentsize;
    memcpy(&TabSectionHeader[j], &buffer[i], header.e_shentsize); 
    TabSectionHeader[j].nameNotid = &buffer[__bswap_32(shstrtab_section.sh_offset) + __bswap_32(TabSectionHeader[j].sh_name)];
  }
}

void print_elf_section_header(Elf32_Ehdr header, Elf32_Shdr_notELF *TabSectionHeader, unsigned char *buffer) {

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

  printf("There are %d section headers, starting at offset 0x%x:\n\nSection Headers:\n  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al\n", header.e_shnum, header.e_shoff);
  for(int i = 0; i < header.e_shnum; i++){

    if (i < 10) printf("  [ %d] ", i); // indice
    else printf("  [%d] ", i);
    
    printf("%-16s  ", TabSectionHeader[i].nameNotid);
    
    for (int j = 0; j < 17; j++)  // Type
    {
      if(__bswap_32(TabSectionHeader[i].sh_type) == typeSection[j]){
        printf("%s",typeSectionNom[j]);
      }
    }
    
    printf("%8.8x ", __bswap_32(TabSectionHeader[i].sh_addr)); // Adresse
    printf("%6.6x ", __bswap_32(TabSectionHeader[i].sh_offset)); // Offset
    printf("%6.6x ", __bswap_32(TabSectionHeader[i].sh_size)); // Size
    printf("%2.2x ", __bswap_32(TabSectionHeader[i].sh_entsize)); // EntSize
    char str_flag[10];
    get_flag(__bswap_32(TabSectionHeader[i].sh_flags),str_flag);
    printf("%3s ",str_flag); // Flags
    printf("%2d ", __bswap_32(TabSectionHeader[i].sh_link)); // Link
    printf("%3d ", __bswap_32(TabSectionHeader[i].sh_info)); // Info
    printf("%2d\n", __bswap_32(TabSectionHeader[i].sh_addralign)); // Align

  }
  printf("Key to Flags:\n  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),\n  L (link order), O (extra OS processing required), G (group), T (TLS),\n  C (compressed), x (unknown), o (OS specific), E (exclude),\n  D (mbind), y (purecode), p (processor specific)\n");
}

void print_elf_header(Elf32_Ehdr header) {

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

  if(argc < 3) printf("Erreur il manque des arguments\n");

  FILE* file = fopen(argv[2], "rb");

  if(file) {

    // Initialisation du Buffer
    fseek( file, 0, SEEK_END);
    unsigned long size = ftell(file);
    unsigned char buffer[size];
    fseek(file, 0, SEEK_SET);
    fread(&buffer, size, 1, file);
    fclose(file);

    // Initialisation du Header
    Elf32_Ehdr header;
    memcpy(&header, &buffer[0], 52);
    swap_header(&header);

    if(is32_B_E(header)){
      printf("ERR_ELF_FILE : Le fichier n'est pas un fichier ELF 32bits big endian\n");
      return 1;
    }

    // Initialisation de la table des sections
    Elf32_Shdr_notELF TabSectionHeader[header.e_shnum];
    init_TabSectionHeader(header, TabSectionHeader, buffer);

    if (!strcmp(argv[1], "-h")) print_elf_header(header);
    else if (!strcmp(argv[1], "-S")) print_elf_section_header(header, TabSectionHeader, buffer );
    else if (!strcmp(argv[1], "-x") && argc == 4) read_elf_section_dump(header, TabSectionHeader, buffer, atoi(argv[3]));
    else if (!strcmp(argv[1], "-s")) read_elf_symbol_table(header, TabSectionHeader, buffer);
    else if (!strcmp(argv[1], "-r")) read_elf_relocation_section(header, TabSectionHeader, buffer);
    else printf("Erreur nombre d'arguments\n");
    return 0;

  }

  printf("ERR_ELF_FILE : Erreur lecture du fichier\n");
  return 1;
}
