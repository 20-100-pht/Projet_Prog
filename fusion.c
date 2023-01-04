#include "fusion.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "lecture.h"

int main(int argc, char *argv[]){

    if(argc < 4){
        fprintf(stderr, "Il manques des arguments");
        return EXIT_FAILURE;
    }

    FILE* fileElf1 = fopen(argv[2], "rb");
    FILE* fileElf2 = fopen(argv[3], "rb");
    FILE* fileElfResult = fopen(argv[4], "wb");

    if(!fileElf1 || !fileElf2 || !fileElfResult){
        printf("ERR_ELF_FILE : Erreur lecture du fichier\n");
        return EXIT_FAILURE;
    }

    struct stat fileInfo;

    stat(argv[2], &fileInfo);
    unsigned char bufferElf1[fileInfo.st_size];
    fread(&bufferElf1, fileInfo.st_size, 1, fileElf1);

    stat(argv[3], &fileInfo);
    unsigned char bufferElf2[fileInfo.st_size];
    fread(&bufferElf2, fileInfo.st_size, 1, fileElf2);

    //Elf *elf1 = read_elf(bufferElf1);
    //Elf *elf2 = read_elf(bufferElf2);

    fclose(fileElf1);
    fclose(fileElf2);
    fclose(fileElfResult);

    return EXIT_SUCCESS;
}

void fusion_sections_progbits(Elf *elf1, Elf *elf2){

}