#include "fusion.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <elf.h>
#include <string.h>

/* Index Code :
  - Fonction Affichage
  - Fonction Fonction Fusion Section PROGBITS, NOBITS, ARM_ATTRIBUTES
  - Fonction Fonction Fusion Table des Symbole
  - Fonction Fonction Fusion Table Relocation
  - Fonction Fonction Fusion Global
*/

/*########## Fonction Affichage ##########*/

void print_fusion(Elf *elfRes){
    print_elf_header(elfRes->header);
    printf("\n\n");
    print_elf_section_header(elfRes->header, elfRes->secHeaders);
    for(int i = 0; i < elfRes->header->e_shnum; i++){
        print_elf_section_dump(elfRes->secHeaders, elfRes->secDumps, i);
    }
    print_elf_symbol_table(elfRes->secHeaders, elfRes->symbolTab, elfRes->strTab, elfRes->nbSym);
}

/*########## Fonction Fusion Section PROGBITS, NOBITS, ARM_ATTRIBUTES ##########*/

void fusion_sections_simpleconcat(Elf *elf1, Elf *elf2, Elf *elfRes, SectionNumberingCorrection *lSecNumCorrection){
    
    int offset = 52;
    for(int i = 0; i < elf1->header->e_shnum; i++){ 

        if(elf1->secHeaders[i].sh_type != SHT_PROGBITS && elf1->secHeaders[i].sh_type != SHT_NOBITS && elf1->secHeaders[i].sh_type != SHT_ARM_ATTRIBUTES) {
            continue;
        }

        elfRes->secHeaders[i].sh_type = elf1->secHeaders[i].sh_type;
        elfRes->secHeaders[i].nameNotid = elf1->secHeaders[i].nameNotid;
        elfRes->secHeaders[i].sh_size = elf1->secHeaders[i].sh_size;
        elfRes->secHeaders[i].sh_offset = offset;

        offset += elf1->secHeaders[i].sh_size;

        int j;
        for(j = 0; j < elf2->header->e_shnum; j++){

            if(elf2->secHeaders[j].sh_type != SHT_PROGBITS && elf2->secHeaders[j].sh_type != SHT_NOBITS && elf2->secHeaders[j].sh_type != SHT_ARM_ATTRIBUTES){
                continue;
            }

            if(memcmp(elf1->secHeaders[i].nameNotid, elf2->secHeaders[j].nameNotid, strlen((const char*)elf1->secHeaders[i].nameNotid)) == 0) {
                if(elf2->secHeaders[j].sh_type != SHT_ARM_ATTRIBUTES){
                    elfRes->secHeaders[i].sh_size += elf2->secHeaders[j].sh_size;
                    offset += elf2->secHeaders[j].sh_size;
                }
                break;
            } 
        }

        //Dans tous les cas on ajoute la section du 1er fichier
        elfRes->secDumps[i] = malloc(elfRes->secHeaders[i].sh_size);
        memcpy(elfRes->secDumps[i], elf1->secDumps[i], elf1->secHeaders[i].sh_size);

        //Et si on a trouvé une section du même nom dans le 2e fichier on la fusionne avec la section du 1er
        if(j != elf2->header->e_shnum){
            //Si c'est une section ARM_ATTRIBUTES alors elle est identique dans les 2 fichiers, on la duplique pas en fusionnant. On corrige juste 
            if(elf2->secHeaders[j].sh_type != SHT_ARM_ATTRIBUTES){
                memcpy(elfRes->secDumps[i]+elf1->secHeaders[i].sh_size, elf2->secDumps[j], elf2->secHeaders[j].sh_size);
                lSecNumCorrection[j].offset = elf1->secHeaders[i].sh_size;
            }
            else{
                lSecNumCorrection[j].offset = 0;
            }
            lSecNumCorrection[j].newNumber = i;
        }
    }

    //On rajoute dans le résultat les sections du 2e fichier qui ne sont pas présente dans le 1er
    int iSec;
    for(int i = 0; i < elf2->header->e_shnum; i++){

        iSec = elf1->header->e_shnum;

        if(elf2->secHeaders[i].sh_type != SHT_PROGBITS && elf2->secHeaders[i].sh_type != SHT_NOBITS && elf2->secHeaders[i].sh_type != SHT_ARM_ATTRIBUTES) {
            continue;
        }
    
        int j;
        for(j = 0; j < elf1->header->e_shnum; j++){
            if(memcmp(elf1->secHeaders[j].nameNotid, elf2->secHeaders[i].nameNotid, strlen((const char*)elf1->secHeaders[i].nameNotid)) == 0){
                break;
            }
        }
        if(j == elf1->header->e_shnum){   

            elfRes->secHeaders[iSec].sh_type = elf1->secHeaders[i].sh_type;
            elfRes->secHeaders[iSec].nameNotid = elf2->secHeaders[i].nameNotid;
            elfRes->secHeaders[iSec].sh_size = elf2->secHeaders[i].sh_size;
            elfRes->secHeaders[iSec].sh_offset = offset;

            elfRes->secDumps[iSec] = malloc(elfRes->secHeaders[iSec].sh_size);
            memcpy(elfRes->secDumps[iSec], elf2->secDumps[i], elf2->secHeaders[i].sh_size);

            lSecNumCorrection[i].newNumber = iSec;
            lSecNumCorrection[i].offset = 0;

            offset += elf2->secHeaders[i].sh_size;
            elfRes->header->e_shnum++;
            
        }
    }
}

/*########## Fonction Fusion Table des Symbole ##########*/

void add_elf1_symbol(Elf *elf, Elf32_Sym *sym, unsigned char* strTab, int *strTabOff){
    add_symbol(elf, sym, strTab, strTabOff);
}

void add_elf2_symbol(Elf *elf, Elf32_Sym *sym, unsigned char* strTab, int *strTabOff, SectionNumberingCorrection* lSecNumCorrection, int *lSymNumCorrection, int symIndex){
    
    if(sym->st_shndx != SHN_ABS && sym->st_shndx != SHN_UNDEF){
        sym->st_value += lSecNumCorrection[sym->st_shndx].offset;
        sym->st_shndx = lSecNumCorrection[sym->st_shndx].newNumber;
    }

    lSymNumCorrection[symIndex] = elf->nbSym;
    
    add_symbol(elf, sym, strTab, strTabOff);
}

void add_symbol(Elf *elf, Elf32_Sym *sym, unsigned char* strTab, int *strTabOff){
    elf->symbolTab[elf->nbSym] = *sym;

    //On corrige l'offset par celui dans la nouvelle table des strings qu'on construit 
    elf->symbolTab[elf->nbSym].st_name = (*strTabOff);
    //On construit la nouvelle table des strings
    const char* sNameAddr = (const char*)strTab + sym->st_name;
    strcpy((char*)(elf->strTab+(*strTabOff)), sNameAddr);
    (*strTabOff) += strlen(sNameAddr)+1;

    elf->nbSym++;
}

void fusion_symbol_tables(Elf *elf1, Elf *elf2, Elf *elfRes, SectionNumberingCorrection* lSecNumCorrection, int *lSymNumCorrection){

    int strTabOff = 1;
    for(int i = 0; i < elf1->nbSym; i++){

        //On ajoute directement les symboles locaux du 1er fichier
        if(ELF32_ST_BIND(elf1->symbolTab[i].st_info) == STB_LOCAL){
            add_elf1_symbol(elfRes, &elf1->symbolTab[i], elf1->strTab, &strTabOff);
            continue;
        }

        int j;
        for(j = 0; j < elf2->nbSym; j++){

            if(strcmp((const char*)(elf1->strTab + elf1->symbolTab[i].st_name), (const char*)(elf2->strTab + elf2->symbolTab[j].st_name)) == 0){

                if(ELF32_ST_BIND(elf2->symbolTab[j].st_info) == STB_GLOBAL){

                    if(elf1->symbolTab[i].st_shndx != SHN_UNDEF && elf2->symbolTab[j].st_shndx != SHN_UNDEF){
                        fprintf(stderr, "ERREUR : Un symbole est défini 2 fois");
                        exit(EXIT_FAILURE);
                    }
                    //Le symbole global est défini seulement dans le 2e fichier et pas dans le 1er
                    else if(elf1->symbolTab[i].st_shndx != SHN_UNDEF && elf2->symbolTab[j].st_shndx == SHN_UNDEF){      
                        add_elf1_symbol(elfRes, &elf1->symbolTab[i], elf1->strTab, &strTabOff);
                        break;
                    }
                    else {  //Le symbole global est défini seulement dans le 1er fichier ou dans les deux
                        add_elf2_symbol(elfRes, &elf2->symbolTab[j], elf2->strTab, &strTabOff, lSecNumCorrection, lSymNumCorrection, j);
                        break;
                    }
                }
            }
        }
        //On ajoute les symboles globaux présent seulement dans le 1er fichier
        if(j == elf2->nbSym){
            add_elf1_symbol(elfRes, &elf1->symbolTab[i], elf1->strTab, &strTabOff);
        }
    }

    //On commence à 1 pour éviter de dupliquer le symbole nul
    for(int i = 1; i < elf2->nbSym; i++){

        if(ELF32_ST_BIND(elf2->symbolTab[i].st_info) == STB_LOCAL){
            //Si c'est un symbole de type section on l'ajoute seulement si il est pas déjà présent dans le 1er fichier
            if(ELF32_ST_TYPE(elf2->symbolTab[i].st_info) != 3 || lSecNumCorrection[elf2->symbolTab[i].st_shndx].newNumber >= elf1->header->e_shnum){
                add_elf2_symbol(elfRes, &elf2->symbolTab[i], elf2->strTab, &strTabOff, lSecNumCorrection, lSymNumCorrection, i);
            } 
        }
        else if(ELF32_ST_BIND(elf2->symbolTab[i].st_info) == STB_GLOBAL){
            int j;
            for(j = 0; j < elf1->nbSym; j++){
                if(strcmp((const char*)(elf2->strTab + elf2->symbolTab[i].st_name), (const char*)(elf1->strTab + elf1->symbolTab[j].st_name)) == 0){
                    break;
                }
            }
            //Si le symbole global est présent seulement dans le 2e fichier on l'ajoute
            if(j == elf1->nbSym){   
                add_elf2_symbol(elfRes, &elf2->symbolTab[i], elf2->strTab, &strTabOff, lSecNumCorrection, lSymNumCorrection, i);
            }
        }
    }
}

/*########## Fonction Fusion Table Relocation ##########*/

void fusion_reimplantations_tables (Elf *elf1, Elf *elf2, Elf *elfRes, SectionNumberingCorrection* lSecNumCorrection, int *lSymNumCorrection){

    for(int i = 0; i < elf1->nbRelocSec; i++){

        int sec1N = elf1->relocSecs[i].iSection;
        for(int j = 0; j < elf2->nbRelocSec; j++){

            int sec2N = elf2->relocSecs[j].iSection;
            if(strcmp((const char*)(elf1->secHeaders[sec1N].nameNotid), (const char*)(elf2->secHeaders[sec2N].nameNotid)) == 0){
                
            }
        }
    }
}

/*########## Fonction Allocation et Liberation Memoire ##########*/

void allocation_elf_resultat(Elf *elf1, Elf *elf2, Elf *elfRes){
    int nSectionMax = elf1->header->e_shnum + elf2->header->e_shnum;
    elfRes->secHeaders = malloc(nSectionMax * sizeof(Elf32_Shdr_notELF));
    elfRes->secDumps = malloc(nSectionMax * sizeof(unsigned char*));
    elfRes->symbolTab = malloc((elf1->nbSym+elf2->nbSym)*sizeof(Elf32_Sym));
    elfRes->strTab = malloc((elf1->nbSym+elf2->nbSym)*30*sizeof(unsigned char));
    elfRes->header = calloc(1,sizeof(Elf32_Ehdr));
    elfRes->relocSecs = malloc((elf1->nbRelocSec+elf2->nbRelocSec)*sizeof(Elf32_RelocSec *));

    // ### réecriture du header dans elfRes ###
    memcpy(elfRes->header, elf1->header, sizeof(Elf32_Ehdr) );
    elfRes->header->e_shstrndx = 0;
    elfRes->header->e_shoff = 0;
    elfRes->header->e_shnum = elf1->header->e_shnum; 

}

void Liberation_Elf(Elf *elf){
    free(elf->header);
    free(elf->symbolTab);
    free(elf);
}

/*########## Fonction Fusion Global ##########*/

int fusion(char file1[],char file2[],char result[]) {

    FILE* fileElf1 = fopen(file1, "rb");
    FILE* fileElf2 = fopen(file2, "rb");
    FILE* fileElfResult = fopen(result, "wb");

    if(!fileElf1 || !fileElf2 || !fileElfResult){
        printf("ERR_ELF_FILE : Erreur lecture du fichier\n");
        return EXIT_FAILURE;
    }

    // ### Lecture des deux fichiers nécessaires à la fusion ###

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

    //unsigned char bufferElfRes[sizeResult];

    Elf *elf1 = read_elf(bufferElf1);
    Elf *elf2 = read_elf(bufferElf2);
    Elf *elfRes = malloc(sizeof(Elf));

    // ### allocation et initialisation struct elf resultat ###
    allocation_elf_resultat(elf1, elf2, elfRes);

    // ### Fusion ###

    SectionNumberingCorrection lSecNumCorrection[elf2->header->e_shnum];
    int lSymNumCorrection[elf2->nbSym];
    

    fusion_sections_simpleconcat(elf1, elf2, elfRes, lSecNumCorrection);
    fusion_symbol_tables(elf1, elf2, elfRes, lSecNumCorrection, lSymNumCorrection);
    fusion_reimplantations_tables(elf1, elf2, elfRes, lSecNumCorrection, lSymNumCorrection);

    // ### Affichage ###

    print_fusion(elfRes);

    // ### Libération mémoire et fermeture fichiers ###

    Liberation_Elf(elf1);
    Liberation_Elf(elf2);
    Liberation_Elf(elfRes);

    fclose(fileElf1);
    fclose(fileElf2);
    fclose(fileElfResult);

    return EXIT_SUCCESS;
}
