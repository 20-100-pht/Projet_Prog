#include "fusion.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <elf.h>
#include <string.h>

#include "lecture.h"



void fusion_sections_simpleconcat(Elf *elf1, Elf *elf2, Elf *elfRes, Elf32_Word sectionType){
    
    int Ind = elfRes->header->e_shnum;
    int Offset = 0;
    
    if(Ind == 0) Offset = 52;
    else {
        Offset = elfRes->secHeaders[Ind].sh_offset + elfRes->secHeaders[Ind].sh_size;
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
            if( elf2->secHeaders[j].sh_type == sectionType && memcmp(elf1->secHeaders[i].nameNotid, elf2->secHeaders[j].nameNotid, 10) == 0 ) {

                printf("Eureka ! : %s\n", elf1->secHeaders[i].nameNotid);  
                elfRes->secHeaders[Ind].sh_size += elf2->secHeaders[j].sh_size;
                Offset += elf2->secHeaders[j].sh_size;

                break;
            } 
        }

        elfRes->secDumps[Ind] = malloc(elfRes->secHeaders[Ind].sh_size);
        memcpy(elfRes->secDumps[Ind], elf1->secDumps[i], elf1->secHeaders[i].sh_size);
        if(j != elf2->header->e_shnum){
            memcpy(elfRes->secDumps[Ind]+elf1->secHeaders[i].sh_size, elf2->secDumps[j], elf2->secHeaders[j].sh_size);
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
            if(memcmp(elf1->secHeaders[j].nameNotid, elf2->secHeaders[i].nameNotid, 10) == 0){
                break;
            }
        }
        if(j == elf1->header->e_shnum){ 
            printf("Eureka ! : %s\n", elf2->secHeaders[i].nameNotid);  

            elfRes->secHeaders[Ind].nameNotid = elf2->secHeaders[i].nameNotid;
            elfRes->secHeaders[Ind].sh_size = elf2->secHeaders[i].sh_size;
            elfRes->secHeaders[Ind].sh_offset = Offset;

            elfRes->secDumps[Ind] = malloc(elfRes->secHeaders[Ind].sh_size);
            memcpy(elfRes->secDumps[Ind], elf2->secDumps[i], elf2->secHeaders[i].sh_size);

            Offset += elf2->secHeaders[i].sh_size;
            Ind++;
        }
    }

    elfRes->header->e_shnum = Ind;
}

void fusion_nobits(Elf *elf1, Elf *elf2, Elf *elfRes){
    fusion_sections_simpleconcat(elf1, elf2, elfRes, SHT_NOBITS);
}

void fusion_progbits(Elf *elf1, Elf *elf2, Elf *elfRes){
    fusion_sections_simpleconcat(elf1, elf2, elfRes, SHT_PROGBITS);
}

void print_fusion(Elf *elfRes){
    printf("nbS : %d", elfRes->header->e_shnum);
    for(int i = 0; i < elfRes->header->e_shnum; i++){
        print_elf_section_dump(elfRes->secHeaders, elfRes->secDumps, i);
    }
}

void fusion_symbol_tables(Elf *elf1, Elf *elf2, Elf *elfRes){

    int strTabOff = 0;
    for(int i = 0; i < elf1->nbSym; i++){
        if(ELF32_ST_BIND(elf1->symbolTab[i].st_info) == STB_LOCAL){
            elfRes->symbolTab[elfRes->nbSym] = elf1->symbolTab[i];
            //strcpy()
            elfRes->nbSym++;
            continue;
        }

        int j;
        for(j = 0; i < elf2->nbSym; j++){
            if(memcmp(elf1->secHeaders[i].nameNotid, elf2->secHeaders[j].nameNotid, 10)){

                if(elf1->symbolTab[i].st_shndx != SHN_UNDEF && elf1->symbolTab[i].st_shndx != SHN_UNDEF){
                    fprintf(stderr, "ERREUR : Un symbole est défini 2 fois");
                    exit(EXIT_FAILURE);
                }
                else if(elf1->symbolTab[i].st_shndx != SHN_UNDEF && elf1->symbolTab[i].st_shndx == SHN_UNDEF){ 
                    elfRes->symbolTab[elfRes->nbSym] = elf1->symbolTab[i];
                    elfRes->nbSym++;
                }
                else {
                    elfRes->symbolTab[elfRes->nbSym] = elf2->symbolTab[i];
                    elfRes->nbSym++;
                }
            }
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
    elfRes->header = calloc(1,sizeof(Elf32_Ehdr));

    int nSectionMax = elf1->header->e_shnum + elf2->header->e_shnum;
    elfRes->secHeaders = malloc(nSectionMax * sizeof(Elf32_Shdr_notELF));
    elfRes->secDumps = malloc(nSectionMax * sizeof(unsigned char*));
    elfRes->symbolTab = malloc((elf1->nbSym+elf2->nbSym)*sizeof(Elf32_Sym));
    elfRes->strTab = malloc((elf1->nbSym+elf2->nbSym)*sizeof(unsigned char));

    //print_global_elf(elf1, bufferElf1);
    //print_global_elf(elf2, bufferElf2);

    fusion_progbits(elf1, elf2, elfRes);
    fusion_nobits(elf1, elf2, elfRes);
    print_fusion(elfRes);

    fclose(fileElf1);
    fclose(fileElf2);
    fclose(fileElfResult);

    return EXIT_SUCCESS;
}