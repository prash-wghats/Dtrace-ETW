


#ifndef _WIN64

//----------------------------------------------------------------------------
__declspec( naked ) void OrbitPrologAsm()
{
    __asm
    {
        push    ebp
        mov     ebp, esp
        push    eax
        push    ecx
        push    edx

        sub     esp, 64
        movdqu xmmword ptr[esp+48], xmm0
        movdqu xmmword ptr[esp+32], xmm1
        movdqu xmmword ptr[esp+16], xmm2
        movdqu xmmword ptr[esp+0],  xmm3

       	//sub     ebp, esp
		sub		eax, esp
        //push    ebp                         // Pass in size of context
		push	eax
        lea     eax, [esp-8]
        push    eax                         // Pass in context
        mov     ecx, 0x12345678             // Pass in address of original function
        push    ecx
        mov     eax, 0x12345678             // Set address of user prolog
        call    eax                         // Call user prolog
        add     esp, 12                     // Clear args from stack frame

        movdqu xmm3, xmmword ptr[esp+0]
        movdqu xmm2, xmmword ptr[esp+16]
        movdqu xmm1, xmmword ptr[esp+32]
        movdqu xmm0, xmmword ptr[esp+48]
        add     esp, 64

        pop     edx
        pop     ecx
        pop     eax
        mov     esp, ebp
        pop     ebp

        //mov     dword ptr[esp], 0x12345678  // Overwrite return address with address of OrbitEpilog
        //mov     eax, 0x12345678             // Address of trampoline to original function
        //jmp     eax                         // Jump to trampoline to original function
		push 0x12345678
		ret
        mov     eax, 0x0FFFFFFF             // Dummy function delimiter, never executed
    }
}

//-----------------------------------------------------------------------------
__declspec( naked ) void OrbitEpilogAsm()
{
    __asm
    {
        push    eax                    // Save eax (return value)
        sub     esp, 16
        movdqu xmmword ptr[ESP], xmm0; // Save XMM0 (float return value)
        mov     ecx, 0x12345678
        push eax                        //return value
        mov     eax, 0x12345678         //Pass in address of original function
        push    eax
        call    ecx                    // Call user epilog (returns original caller address)
        add     esp, 8
        mov     edx, eax               // edx contains caller address
        movdqu xmm0, xmmword ptr[ESP]; // XMM0 contains float return value
        add     ESP, 16
        pop     eax                    // eax contains return value
        //push    edx                    // Push caller address on stack
        ret
        mov     eax, 0x0FFFFFFF        // Dummy function delimiter, never executed
    }
}

#endif

