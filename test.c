void print_elf_symbol_table(Elf32_Ehdr header, Elf32_Shdr_notELF *TabSectionHeader, unsigned char *buffer, Elf32_Sym symbolTable, unsigned char *strTab) {
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

    printf("\nSymbol table '.symtab' contains %d entries:\n   Num:    Value  Size Type    Bind   Vis      Ndx Name\n",size);

    int size = 0;
    for (int s = 0; s < header.e_shnum; s++) {
        if (__bswap_32(TabSectionHeader[s].sh_type) == SHT_SYMTAB) {
            size = __bswap_32(TabSectionHeader[s].sh_size) / sizeof(Elf32_Sym);
        }
    }

    for (int j = 0; j < size; j++) {
        printf("   %3d: ",j); // Num
        printf("%8.8x  ", __bswap_32(symbolTable[j].st_value)); // Val
        printf("%4d ", __bswap_32(symbolTable[j].st_size)); // Size
        printf("%s", typeSectionNom[symbolTable[j].st_info]); // Type
        printf("%s", bindType[symbolTable[j].st_info >> 4]); //Bind
        printf("%s", visType[symbolTable[j].st_other]); // Vis

        //Chaque type d'index
        for (int i; i < 9; i++) {
            if(__bswap_16(symbolTable[j].st_shndx) != indType[i]) continue;
            printf("%s", indTypeNom[i]); // Ndx
            break;
        }

        //Si type est section alors shstrtab sinon strtab
        if(symbolTable[j].st_info == 3){
            printf("%s\n", TabSectionHeader[i].nameNotid); // Name
        }
        else{
            printf("%s\n", strTab + __bswap_32(symbolTable[j].st_name)); //Name
        }
    }
}

void read_elf_symbol_table(Elf32_Ehdr header, Elf32_Shdr_notELF *TabSectionHeader, unsigned char *buffer, Elf32_Sym symbolTable, unsigned char *strTab) {
  int size = 0;

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

    // Si table des str
    if (__bswap_32(TabSectionHeader[i].sh_type) == SHT_STRTAB){
      //adresse de la table str
      strTab = &buffer[__bswap_32(TabSectionHeader[i].sh_addr)+__bswap_32(TabSectionHeader[i].sh_offset)];
      break;
    };
  }
}




////////////


void read_elf_symbol_table(Elf32_Ehdr header, Elf32_Shdr_notELF *TabSectionHeader, unsigned char *buffer) {
  Elf32_Sym *symbolTable = NULL;
  //Pointeur vers la table str
  unsigned char *strTab;
  int size = 0;

  //On cherche la table des symbole et de str
  for (int i = 0; i < header.e_shnum; i++) {

    //Si table des symboles
    if (TabSectionHeader[i].sh_type == SHT_SYMTAB){
      //Prendre le nombre d'entrees
      size = TabSectionHeader[i].sh_size / sizeof(Elf32_Sym);
      symbolTable = malloc(size * sizeof(Elf32_Sym));
      //Copy de la table symboles
      memcpy(symbolTable, &buffer[TabSectionHeader[i].sh_offset], size * sizeof(Elf32_Sym));
    };

    if (__bswap_32(TabSectionHeader[i].sh_type) == SHT_STRTAB){
      //adresse de la table str
      strTab = &buffer[TabSectionHeader[i].sh_addr+TabSectionHeader[i].sh_offset];
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









/////////////////////////////////////////////


void read_elf_relocation_section(Elf32_Ehdr header, Elf32_Shdr_notELF *TabSectionHeader, unsigned char *buffer) {
  Elf32_Rel *relocSect = NULL;
  Elf32_Sym *symbolTable = NULL;

  unsigned char *strTab;
  int size=0;
  int offset=0;
  int aa=0;
  //On cherche la section reloc
  for (int i = 0; i < header.e_shnum; i++) {
    //Si reloc
    if (__bswap_32(TabSectionHeader[i].sh_type) == SHT_REL){
      size = __bswap_32(TabSectionHeader[i].sh_size) / sizeof(Elf32_Rel);
      relocSect = malloc(__bswap_32(TabSectionHeader[i].sh_size));
      offset=__bswap_32(TabSectionHeader[i].sh_offset);
      //Copie de la section reloc
      memcpy(relocSect, &buffer[__bswap_32(TabSectionHeader[i].sh_offset)], __bswap_32(TabSectionHeader[i].sh_size));
    };

    if (__bswap_32(TabSectionHeader[i].sh_type) == SHT_STRTAB && aa == 0){
      //adresse de la table str
      strTab = &buffer[__bswap_32(TabSectionHeader[i].sh_offset)];
      aa =1;
    };

    //Si table des symboles
    if (__bswap_32(TabSectionHeader[i].sh_type) == SHT_SYMTAB){
      //Prendre le nombre d'entrees
      int size2 = __bswap_32(TabSectionHeader[i].sh_size) / sizeof(Elf32_Sym);
      symbolTable = malloc(size2 * sizeof(Elf32_Sym));
      //Copy de la table symboles
      memcpy(symbolTable, &buffer[__bswap_32(TabSectionHeader[i].sh_addr) +__bswap_32(TabSectionHeader[i].sh_offset)], size2 * sizeof(Elf32_Sym));
    };
  }

  char *numEnt;
  if(size == 1){
    numEnt="entry";
  }else{
    numEnt="entries";
  }
  
  printf("\nRelocation section '.rel.text' at offset 0x%x contains %d %s:\n Offset     Info    Type            Sym.Value  Sym. Name\n",offset,size,numEnt);
  for (int i = 0; i < size; i++)
  {
    printf("%8.8x  ",__bswap_32(relocSect[i].r_offset));
    printf("%8.8x ",__bswap_32(relocSect[i].r_info));
    
    switch (ELF32_R_TYPE(__bswap_32(relocSect[i].r_info)))
    {
    case R_ARM_CALL:
      printf("R_ARM_CALL       ");
      break;
    case R_ARM_ABS32:
      printf("R_ARM_ABS32      ");
      break;
    case R_ARM_V4BX:
      printf("R_ARM_V4BX       ");
      break;
    default:
      break;
    }

    int symInd = (__bswap_32(relocSect[i].r_info)>>8);
    if(symInd == 0){
      printf("\n");
      continue;
    } 
    printf(" %8.8x   ",__bswap_32(symbolTable[symInd].st_value));

    //Si type est section alors shstrtab sinon strtab
    if(__bswap_32(symbolTable[symInd].st_name) == 0){
      printf("%s\n", TabSectionHeader[symInd].nameNotid); // Name
    }else{
      printf("%s\n", strTab + __bswap_32(symbolTable[symInd].st_name));// Name
    }    
  }

}




//////////////////////////////////////////////


void read_elf_relocation_section(unsigned char *buffer, Elf *elf) {

  //On cherche la section relocation
  for (int i = 0; i < elf->header->e_shnum; i++) {
    //Si relocation
    if (elf->tabSectionHeader[i].sh_type == SHT_REL){
      elf->Reloc->nbReloc = elf->tabSectionHeader[i].sh_size / sizeof(Elf32_Rel);
      elf->relocSect = malloc(elf->tabSectionHeader[i].sh_size);
      elf->Reloc->offset = elf->tabSectionHeader[i].sh_offset;
      //Copie de la section reloc
      memcpy(elf->relocSect, &buffer[elf->tabSectionHeader[i].sh_offset], elf->tabSectionHeader[i].sh_size);
    }
  }
}

void print_elf_relocation_section(unsigned char *buffer, Elf *elf) {

  char *numEnt;
  if(elf->Reloc->nb == 1){
    numEnt="entry";
  }else{
    numEnt="entries";
  }
  
  printf("\nRelocation section '.rel.text' at offset 0x%x contains %d %s:\n Offset     Info    Type            Sym.Value  Sym. Name\n",elf->Reloc->offset, elf->Reloc->nb, numEnt);
  for (int i = 0; i < elf->Reloc->nb; i++)
  {
    printf("%8.8x  ",__bswap_32(elf->Reloc->Sect[i].r_offset));
    printf("%8.8x ",__bswap_32(elf->Reloc->Sect[i].r_info));
    
    switch (ELF32_R_TYPE(__bswap_32(elf->Reloc->Sect[i].r_info)))
    {
    case R_ARM_CALL:
      printf("R_ARM_CALL       ");
      break;
    case R_ARM_ABS32:
      printf("R_ARM_ABS32      ");
      break;
    case R_ARM_V4BX:
      printf("R_ARM_V4BX       ");
      break;
    default:
      break;
    }

    int symInd = (__bswap_32(elf->Reloc->Sect[i].r_info)>>8);
    if(symInd == 0){
      printf("\n");
      continue;
    } 
    printf(" %8.8x   ",__bswap_32(elf->symbolTab[symInd].st_value));

    //Si type est section alors shstrtab sinon strtab
    if(__bswap_32(elf->symbolTab[symInd].st_name) == 0){
      printf("%s\n", elf->secHeaders[symInd].nameNotid); // Name
    }else{
      printf("%s\n", elf->strTab + __bswap_32(elf->symbolTab[symInd].st_name));// Name
    }    
  }

}