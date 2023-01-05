#include "fusion.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <elf.h>
#include <string.h>

#include "lecture.h"

void fusion_sections_progbits(Elf *elf1, Elf *elf2, Elf *elfRes, unsigned char *bufferElf1, unsigned char *bufferElf2, unsigned char *bufferElfRes){
    
    int progbInd = 0;
    int progbOffset = 0;
    for(int i=0; i < elf1->header->e_shnum; i++){
        if( elf1->secHeaders[i].sh_type != SHT_PROGBITS){
            continue;
        }

        for(int j = 0; j < elf2->header->e_shnum; j++){
            if( elf2->secHeaders[j].sh_type == SHT_PROGBITS && memcmp(elf1->secHeaders[i].nameNotid, elf2->secHeaders[j].nameNotid, 10) == 0 ) {
                printf("Eureka ! : %s\n", elf1->secHeaders[i].nameNotid);
                elfRes->secHeaders[progbInd].nameNotid = elf1->secHeaders[i].nameNotid;
                elfRes->secHeaders[progbInd].sh_size = elf1->secHeaders[i].sh_size + elf2->secHeaders[j].sh_size;
                elfRes->secHeaders[progbInd].sh_offset = progbOffset;
                progbInd++;
                progbOffset += elfRes->secHeaders[progbInd].sh_offset + elf1->secHeaders[i].sh_size + elf2->secHeaders[j].sh_size;
                
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
    elfRes->header = malloc(sizeof(Elf32_Ehdr));
    elfRes->secHeaders = malloc((elf1->header->e_shnum + elf2->header->e_shnum) * sizeof(Elf32_Shdr_notELF));

    //print_global_elf(elf1, bufferElf1);
    //print_global_elf(elf2, bufferElf2);

    fusion_sections_progbits(elf1, elf2, elfRes, bufferElf1, bufferElf2, bufferElfRes);

    fclose(fileElf1);
    fclose(fileElf2);
    fclose(fileElfResult);

    return EXIT_SUCCESS;
}