#ifndef OFF_H
#define OFF_H

#include <stdint.h>
#include <excpt.h>

void InitOff();
enum OrbitPrologOffset
{
    Prolog_OriginalFunction = 0,
    Prolog_CallbackAddress,
    //Prolog_EpilogAddress,
    Prolog_OriginalAddress,
    Prolog_NumOffsets
};

//-----------------------------------------------------------------------------
struct Prolog
{
    char*  m_Code;
    size_t m_Size;
    size_t m_Offsets[Prolog_NumOffsets];
};

//-----------------------------------------------------------------------------
enum OrbitEpilogOffset
{
    Epilog_CallbackAddress = 0,
    Epilog_OriginalFunction,
    Epilog_NumOffsets
};

//-----------------------------------------------------------------------------
struct Epilog
{
    char*  m_Code;
    size_t m_Size;
    size_t m_Offsets[Epilog_NumOffsets];
};

#define EPILOG_CODE_SKIP 0
#define EPILOG_CODE_OFFSET 4

#pragma pack(push, 1)
//-----------------------------------------------------------------------------
struct OrbitSSEContext
{
    M128A xmm0;
    M128A xmm1;
    M128A xmm2;
    M128A xmm3;
    M128A xmm4;
    M128A xmm5;
    M128A xmm6;
    M128A xmm7;
    M128A xmm8;
    M128A xmm9;
    M128A xmm10;
    M128A xmm11;
    M128A xmm12;
    M128A xmm13;
    M128A xmm14;
    M128A xmm15;
};
#pragma pack(pop)


#ifdef _cplusplus
#ifdef _WIN64
extern "C" void OrbitGetSSEContext(struct OrbitSSEContext * a_Context );
extern "C" void OrbitSetSSEContext(struct OrbitSSEContext * a_Context );
#endif
extern "C" void OrbitPrologAsm();
extern "C" void OrbitEpilogAsm();
#else
#ifdef _WIN64
void OrbitGetSSEContext(struct OrbitSSEContext * a_Context );
void OrbitSetSSEContext(struct OrbitSSEContext * a_Context );
#endif
void OrbitPrologAsm(void);
void OrbitEpilogAsm(void);
#endif



extern struct Prolog prolog;
extern struct Epilog epilog;
extern struct Epilog handler;
#endif