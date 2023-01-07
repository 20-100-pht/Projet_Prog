#pragma once

#define ELF32_ST_BIND(i) ((i)>>4)
#define ELF32_ST_TYPE(i) ((i)&0xf)
#define ELF32_ST_INFO(b,t) (((b)<<4)+((t)&0xf))
#define STB_LOCAL 0
#define STB_GLOBAL 0

int fusion(char file1[],char file2[],char result[]);

typedef struct {
    int newNumber;
    int offset;
} SectionNumberingCorrection;

