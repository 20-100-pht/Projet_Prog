#include "fusion.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <elf.h>
#include <string.h>
#include <stdbool.h>

#include "lecture.h"



void fusion_sections_simpleconcat(Elf *elf1, Elf *elf2, Elf *elfRes, Elf32_Word sectionType, SectionNumberingCorrection *lSecNumCorrection){
    
    int Ind = elfRes->header->e_shnum;
    int Offset = 0;
    int iSecNumCorr = 0;
    
    if(Ind == 0) Offset = 52;
    else {
        Offset = elfRes->secHeaders[Ind-1].sh_offset + elfRes->secHeaders[Ind-1].sh_size;
    }

    for(int i = 0; i < elf1->header->e_shnum; i++){ 

        if(elf1->secHeaders[i].sh_type != sectionType) {
            continue;
        }

        elfRes->secHeaders[Ind].nameNotid = elf1->secHeaders[i].nameNotid;
        elfRes->secHeaders[Ind].sh_size = elf1->secHeaders[i].sh_size;
        elfRes->secHeaders[Ind].sh_offset = Offset;

        Offset += elf1->secHeaders[i].sh_size;

        int j;
        for(j = 0; j < elf2->header->e_shnum; j++){
            if( elf2->secHeaders[j].sh_type == sectionType && memcmp(elf1->secHeaders[i].nameNotid, elf2->secHeaders[j].nameNotid, strlen((const char*)elf1->secHeaders[i].nameNotid)) == 0 ) {

                //printf("Eureka ! : %s\n", elf1->secHeaders[i].nameNotid);  
                elfRes->secHeaders[Ind].sh_size += elf2->secHeaders[j].sh_size;
                Offset += elf2->secHeaders[j].sh_size;

                break;
            } 
        }

        elfRes->secDumps[Ind] = malloc(elfRes->secHeaders[Ind].sh_size);
        memcpy(elfRes->secDumps[Ind], elf1->secDumps[i], elf1->secHeaders[i].sh_size);

        if(j != elf2->header->e_shnum){
            memcpy(elfRes->secDumps[Ind]+elf1->secHeaders[i].sh_size, elf2->secDumps[j], elf2->secHeaders[j].sh_size);
            if(sectionType == SHT_PROGBITS){
                lSecNumCorrection[iSecNumCorr].newNumber = Ind;
                lSecNumCorrection[iSecNumCorr].offset = elf1->secHeaders[i].sh_size;
                iSecNumCorr++;
            }
        }
        Ind++;
    }

    //On rajoute dans le résultat les sections du 2e fichier qui ne sont pas présente dans le 1er
    for(int i = 0; i < elf2->header->e_shnum; i++){

        if(elf2->secHeaders[i].sh_type != sectionType) {
            continue;
        }
    
        int j;
        for(j = 0; j < elf1->header->e_shnum; j++){
            if(memcmp(elf1->secHeaders[j].nameNotid, elf2->secHeaders[i].nameNotid, strlen((const char*)elf1->secHeaders[i].nameNotid)) == 0){
                break;
            }
        }
        if(j == elf1->header->e_shnum){ 
            //printf("Eureka ! : %s\n", elf2->secHeaders[i].nameNotid);  

            elfRes->secHeaders[Ind].nameNotid = elf2->secHeaders[i].nameNotid;
            elfRes->secHeaders[Ind].sh_size = elf2->secHeaders[i].sh_size;
            elfRes->secHeaders[Ind].sh_offset = Offset;

            elfRes->secDumps[Ind] = malloc(elfRes->secHeaders[Ind].sh_size);
            memcpy(elfRes->secDumps[Ind], elf2->secDumps[i], elf2->secHeaders[i].sh_size);

            if(sectionType == SHT_PROGBITS){
                lSecNumCorrection[iSecNumCorr].newNumber = Ind;
                lSecNumCorrection[iSecNumCorr].offset = 0;
                iSecNumCorr++;
            }

            Offset += elf2->secHeaders[i].sh_size;
            Ind++;
        }
    }

    elfRes->header->e_shnum = Ind;
}

void fusion_nobits(Elf *elf1, Elf *elf2, Elf *elfRes){
    fusion_sections_simpleconcat(elf1, elf2, elfRes, SHT_NOBITS, NULL);
}

void fusion_progbits(Elf *elf1, Elf *elf2, Elf *elfRes, SectionNumberingCorrection *lSecNumCorrection){
    fusion_sections_simpleconcat(elf1, elf2, elfRes, SHT_PROGBITS, lSecNumCorrection);
}

void print_fusion(Elf *elfRes){
    printf("nbS : %d", elfRes->header->e_shnum);
    for(int i = 0; i < elfRes->header->e_shnum; i++){
        print_elf_section_dump(elfRes->secHeaders, elfRes->secDumps, i);
    }
    print_elf_symbol_table(elfRes->secHeaders, elfRes->symbolTab, elfRes->strTab, elfRes->nbSym);
}

void add_symbol(Elf *elf, Elf32_Sym *sym, unsigned char* strTab, int *strTabOff, bool doSymValueCorrection, SectionNumberingCorrection* lSecNumCorrection){

    if(doSymValueCorrection && ELF32_ST_TYPE(sym->st_info) == 3){
        sym->st_value += lSecNumCorrection[sym->st_shndx].offset;
        sym->st_shndx = lSecNumCorrection[sym->st_shndx].newNumber;
    }

    elf->symbolTab[elf->nbSym] = *sym;

    //On corrige l'offset du nom dy symbole dans la table des strings
    elf->symbolTab[elf->nbSym].st_name = (*strTabOff);
    const char* sNameAddr = (const char*)strTab + sym->st_name;
    strcpy(elf->strTab+(*strTabOff), sNameAddr);
    (*strTabOff) += strlen(sNameAddr)+1;
    elf->nbSym++;
}

void fusion_symbol_tables(Elf *elf1, Elf *elf2, Elf *elfRes, SectionNumberingCorrection* lSecNumCorrection){

    int strTabOff = 1;
    for(int i = 0; i < elf1->nbSym; i++){
        /*if(ELF32_ST_BIND(elf1->symbolTab[i].st_info) == STB_LOCAL){
            add_symbol(elfRes, &elf1->symbolTab[i], elf1->strTab, &strTabOff);
            continue;
        }*/

        int j;
        for(j = 0; j < elf2->nbSym; j++){

            if(strcmp((const char*)(elf1->strTab + elf1->symbolTab[i].st_name), (const char*)(elf2->strTab + elf2->symbolTab[j].st_name)) == 0){

                if(ELF32_ST_BIND(elf2->symbolTab[j].st_info) == STB_LOCAL){
                    if(ELF32_ST_TYPE(elf1->symbolTab[i].st_info) == 3 && ELF32_ST_TYPE(elf2->symbolTab[j].st_info) == 3 && elf1->symbolTab[i].st_shndx == elf2->symbolTab[j].st_shndx){
                        break;
                    }
                }
                else{

                    if(elf1->symbolTab[i].st_shndx != SHN_UNDEF && elf2->symbolTab[j].st_shndx != SHN_UNDEF){
                        fprintf(stderr, "ERREUR : Un symbole est défini 2 fois");
                        exit(EXIT_FAILURE);
                    }
                    else if(elf1->symbolTab[i].st_shndx != SHN_UNDEF && elf2->symbolTab[j].st_shndx == SHN_UNDEF){
                        add_symbol(elfRes, &elf1->symbolTab[i], elf1->strTab, &strTabOff, false, lSecNumCorrection);
                        break;
                    }
                    else {
                        add_symbol(elfRes, &elf2->symbolTab[i], elf2->strTab, &strTabOff, true, lSecNumCorrection);
                        break;
                    }
                }
            }
        }
        //Le symbole global est seulement dans le 1er fichier
        if(j == elf2->nbSym){
            add_symbol(elfRes, &elf1->symbolTab[i], elf1->strTab, &strTabOff, true, lSecNumCorrection);
        }
    }

    for(int i = 0; i < elf2->nbSym; i++){

        if(ELF32_ST_BIND(elf2->symbolTab[i].st_info) == STB_LOCAL){
            add_symbol(elfRes, &elf2->symbolTab[i], elf2->strTab, &strTabOff, true, lSecNumCorrection); 
            continue;
        }

        int j;
        for(j = 0; j < elf1->nbSym; j++){
            if(strcmp((const char*)(elf2->strTab + elf2->symbolTab[i].st_name), (const char*)(elf1->strTab + elf1->symbolTab[j].st_name)) == 0){
                break;
            }
        }
        if(j == elf1->nbSym){
            add_symbol(elfRes, &elf2->symbolTab[i], elf2->strTab, &strTabOff, true, lSecNumCorrection);
        }
    }
}

int fusion(char file1[],char file2[],char result[]) {

    FILE* fileElf1 = fopen(file1, "rb");
    FILE* fileElf2 = fopen(file2, "rb");
    FILE* fileElfResult = fopen(result, "wb");

    if(!fileElf1 || !fileElf2 || !fileElfResult){
        printf("ERR_ELF_FILE : Erreur lecture du fichier\n");
        return EXIT_FAILURE;
    }

    int sizeResult = 0;

    struct stat fileInfo;

    stat(file1, &fileInfo);
    unsigned char bufferElf1[fileInfo.st_size];
    sizeResult = fileInfo.st_size;
    fread(&bufferElf1, fileInfo.st_size, 1, fileElf1);

    stat(file2, &fileInfo);
    unsigned char bufferElf2[fileInfo.st_size];
    sizeResult += fileInfo.st_size;
    fread(&bufferElf2, fileInfo.st_size, 1, fileElf2);

    unsigned char bufferElfRes[sizeResult];

    Elf *elf1 = read_elf(bufferElf1);
    Elf *elf2 = read_elf(bufferElf2);
    Elf *elfRes = malloc(sizeof(Elf));

    int nSectionMax = elf1->header->e_shnum + elf2->header->e_shnum;
    elfRes->secHeaders = malloc(nSectionMax * sizeof(Elf32_Shdr_notELF));
    elfRes->secDumps = malloc(nSectionMax * sizeof(unsigned char*));
    elfRes->symbolTab = malloc((elf1->nbSym+elf2->nbSym)*sizeof(Elf32_Sym));
    elfRes->strTab = malloc((elf1->nbSym+elf2->nbSym)*30*sizeof(unsigned char));
    elfRes->header = calloc(1,sizeof(Elf32_Ehdr));

    SectionNumberingCorrection lSecNumCorrection[elf2->header->e_shnum];

    //print_global_elf(elf1, bufferElf1);
    //print_global_elf(elf2, bufferElf2);

    fusion_progbits(elf1, elf2, elfRes, lSecNumCorrection);
    fusion_nobits(elf1, elf2, elfRes);
    fusion_symbol_tables(elf1, elf2, elfRes, lSecNumCorrection);

    print_fusion(elfRes);

    fclose(fileElf1);
    fclose(fileElf2);
    fclose(fileElfResult);

    return EXIT_SUCCESS;
}