#include <windows.h>
#include "off.h"

struct Prolog prolog = {0};
struct Epilog epilog = {0};


#ifdef _WIN64
char dummyEnd[]     = { 0x49, 0xBB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F };
char dummyAddress[] = { 0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01 };
#else
char dummyEnd[]     = { 0xB8, 0xFF, 0xFF, 0xFF, 0x0F };
char dummyAddress[] = { 0x78, 0x56, 0x34, 0x12 };
#endif

#define NELEMS(a) sizeof(a) / sizeof(a[0])
size_t
FindSize( char* a_Code, size_t a_MaxBytes )
{
	size_t matchSize = NELEMS(dummyEnd);

	for( size_t i = 0; i < a_MaxBytes; ++i ) {
		int j = 0;
		for( j = 0; j < matchSize; ++j ) {
			if( a_Code[i+j] != dummyEnd[j] )
				break;
		}

		if( j == matchSize )
			return i;
	}

	return 0;
}

size_t *
FindOffsets( char* a_Code, size_t a_NumOffsets, char a_Identifier[8],
    size_t matchSize, size_t *offsets, size_t a_MaxBytes )
{

	int off = 0;

	for( size_t i = 0; i < a_MaxBytes; ++i ) {
		int j = 0;
		for( j = 0; j < matchSize; ++j ) {
			if( a_Code[i + j] != a_Identifier[j] )
				break;
		}

		if( j == matchSize ) {
			offsets[off++] = i;
			i += matchSize;
			if(off == a_NumOffsets )
				break;
		}
	}

	return offsets;
}

void
InitOff()
{
	prolog.m_Code = (char*)&OrbitPrologAsm;
	prolog.m_Size = FindSize( prolog.m_Code, 1024 );
	FindOffsets( prolog.m_Code, Prolog_NumOffsets, dummyAddress, NELEMS(dummyAddress), prolog.m_Offsets, 1024);
	epilog.m_Code = (char*)&OrbitEpilogAsm;
	epilog.m_Size = FindSize( epilog.m_Code,1024 );
	FindOffsets( epilog.m_Code, Epilog_NumOffsets, dummyAddress, NELEMS(dummyAddress), epilog.m_Offsets, 1024);
}