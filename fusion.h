#pragma once
#include <stdbool.h>
#include "lecture.h"

/*########## Structure ##########*/

typedef struct {
    int newNumber;
    int offset;
} SectionNumberingCorrection;

/*########## Fonction Affichage ##########*/

void print_fusion(Elf *elfRes);

/*########## Fonction Fusion Section PROGBITS, NOBITS, ARM_ATTRIBUTES ##########*/

void fusion_sections_simpleconcat(Elf *elf1, Elf *elf2, Elf *elfRes, SectionNumberingCorrection *lSecNumCorrection);

/*########## Fonction Fusion Table des Symbole ##########*/

void add_symbol(Elf *elf, Elf32_Sym *sym, unsigned char* strTab, int *strTabOff);
void add_elf1_symbol(Elf *elf, Elf32_Sym *sym, unsigned char* strTab, int *strTabOff);
void add_elf2_symbol(Elf *elf, Elf32_Sym *sym, unsigned char* strTab, int *strTabOff, SectionNumberingCorrection* lSecNumCorrection, int *lSymNumCorrection, int symIndex);

void fusion_symbol_tables(Elf *elf1, Elf *elf2, Elf *elfRes, SectionNumberingCorrection* lSecNumCorrection, int *lSymNumCorrection);

/*########## Fonction Fusion Table Relocation ##########*/

void fusion_reimplantations_tables (Elf *elf1, Elf *elf2, Elf *elfRes, SectionNumberingCorrection* lSecNumCorrection, int *lSymNumCorrection);

/*########## Fonction Allocation et Liberation Memoire ##########*/

void allocation_elf_resultat(Elf *elf1, Elf *elf2, Elf *elfRes);

void liberation_elf(Elf *elf);

/*########## Fonction Fusion Global ##########*/

int fusion(char file1[],char file2[],char result[]);
