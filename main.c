#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <byteswap.h>
#include <ctype.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "lecture.h"
#include "fusion.h"

int main(int argc, char *argv[]){

    if( argc < 2 ) {
        printf("Erreur il manque des arguments\n");
        return EXIT_FAILURE;
    }

    if(!strcmp(argv[1], "-f")){

        if(argc < 5){
            printf("Erreur il manque des arguments\n");
            return EXIT_FAILURE;
        }
        //file1.o file2.o fileResult.o
        fusion(argv[2],argv[3],argv[4]);
    }
    else if(!strcmp(argv[1], "-l")) {
        //-l choix_lecture nom_fichier (option pour -x)

        if(argc < 4){
            printf("Erreur il manque des arguments\n");
            return EXIT_FAILURE;
        }

        FILE* file = fopen(argv[3], "rb");
        if(file) {

        // Initialisation du Buffer
        struct stat fileInfo;
        stat(argv[3], &fileInfo);
        unsigned char buffer[fileInfo.st_size];
        fread(&buffer, fileInfo.st_size, 1, file);
        fclose(file);

        Elf *elf = read_elf(buffer);

        if (!strcmp(argv[2], "-a")) print_global_elf(elf, buffer);
        else if (!strcmp(argv[2], "-h")) print_elf_header(elf->header);
        else if (!strcmp(argv[2], "-S")) print_elf_section_header(elf->header, elf->secHeaders, buffer);
        else if (!strcmp(argv[2], "-x") && argc == 5) print_elf_section_dump(elf->secHeaders, elf->secDumps, atoi(argv[4]));
        else if (!strcmp(argv[2], "-s")) print_elf_symbol_table(elf->header, elf->secHeaders, buffer, elf->symbolTab, elf->strTab, elf->nbSym);
        else if (!strcmp(argv[2], "-r")) print_elf_relocation_section(elf->header, elf->secHeaders, buffer, elf->symbolTab, elf->strTab, elf->Reloc.Sect, elf->Reloc.nb, elf->Reloc.offset);
        else printf("Erreur nombre d'arguments\n");
        }
        else{
        printf("ERR_ELF_FILE : Erreur lecture du fichier\n");
        }

        return EXIT_SUCCESS;
    }
    else {
        printf("Erreur d'arguments\n");
        return EXIT_FAILURE;
    }
}