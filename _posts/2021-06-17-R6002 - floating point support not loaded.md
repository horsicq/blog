Sometimes we can unpack protected executables in Windows but there is a runtime error

```assembly
Microsoft Visual C++ Runtime Library

Runtime Error!

Program: ***.unp.exe

R6002

- floating point support not loaded
```
 
There is some info in UPX sources: [https://github.com/upx/upx/blob/8d42b12117130b944023335cc2b76072c145db4d/src/p_w32pe.cpp#L200](https://github.com/upx/upx/blob/8d42b12117130b944023335cc2b76072c145db4d/src/p_w32pe.cpp#L200)

```assembly
// This works around a "protection" introduced in MSVCRT80, which
// works like this:
// When the compiler detects that it would link in some code from its
// C runtime library which references some data in a read only
// section then it compiles in a runtime check whether that data is
// still in a read only section by looking at the pe header of the
// file. If this check fails the runtime does "interesting" things
// like not running the floating point initialization code - the result
// is a R6002 runtime error.
// These supposed to be read only addresses are covered by the sections
// UPX0 & UPX1 in the compressed files, so we have to patch the PE header
// in the memory. And the page on which the PE header is stored is read
// only so we must make it rw, fix the flags (i.e. clear
// PEFL_WRITE of osection[x].flags), and make it ro again.
```

**This code raises the exception:**

```assembly
.xvlk:0045A560 __IsNonwritableInCurrentImage proc near ; CODE XREF: __except_handler4+FF p
.xvlk:0045A560                                         ; __cinit+E p
.xvlk:0045A560                                         ; __cinit+79 p
.xvlk:0045A560                                         ; __endthreadex+E p
.xvlk:0045A560                                         ; _threadstartex(x)+6A p
.xvlk:0045A560
.xvlk:0045A560 ms_exc          = CPPEH_RECORD ptr -18h
.xvlk:0045A560 arg_0           = dword ptr  8
.xvlk:0045A560
.xvlk:0045A560                 push    ebp
.xvlk:0045A561                 mov     ebp, esp
.xvlk:0045A563                 push    0FFFFFFFEh
.xvlk:0045A565                 push    offset stru_4D2228
.xvlk:0045A56A                 push    offset __except_handler4
.xvlk:0045A56F                 mov     eax, large fs:0
.xvlk:0045A575                 push    eax
.xvlk:0045A576                 sub     esp, 8
.xvlk:0045A579                 push    ebx
.xvlk:0045A57A                 push    esi
.xvlk:0045A57B                 push    edi
.xvlk:0045A57C                 mov     eax, dword_4D7A00
.xvlk:0045A581                 xor     [ebp+ms_exc.registration.ScopeTable], eax
.xvlk:0045A584                 xor     eax, ebp
.xvlk:0045A586                 push    eax
.xvlk:0045A587                 lea     eax, [ebp+ms_exc.registration]
.xvlk:0045A58A                 mov     large fs:0, eax
.xvlk:0045A590                 mov     [ebp+ms_exc.old_esp], esp
.xvlk:0045A593                 mov     [ebp+ms_exc.registration.TryLevel], 0
.xvlk:0045A59A                 push    offset __ImageBase
.xvlk:0045A59F                 call    __ValidateImageBase
.xvlk:0045A5A4                 add     esp, 4
.xvlk:0045A5A7                 test    eax, eax
.xvlk:0045A5A9                 jz      short loc_45A600
.xvlk:0045A5AB                 mov     eax, [ebp+arg_0]
.xvlk:0045A5AE                 sub     eax, offset __ImageBase
.xvlk:0045A5B3                 push    eax
.xvlk:0045A5B4                 push    offset __ImageBase
.xvlk:0045A5B9                 call    __FindPESection
.xvlk:0045A5BE                 add     esp, 8
.xvlk:0045A5C1                 test    eax, eax
.xvlk:0045A5C3                 jz      short loc_45A600

.xvlk:0045A5C5                 mov     eax, [eax+24h]
.xvlk:0045A5C8                 shr     eax, 1Fh
.xvlk:0045A5CB                 not     eax
.xvlk:0045A5CD                 and     eax, 1
```

**I am using the trick in my projects to fix it**

```assembly
if(pDumpOptions->bPatchNWError6002)
{
    //   004947D5  |.  8B40 24                      MOV EAX,DWORD PTR DS:[EAX+24]
    //   004947D8  |.  C1E8 1F                      SHR EAX,1F
    //   004947DB  |.  F7D0                         NOT EAX
    //   004947DD  |.  83E0 01                      AND EAX,00000001
    qint64 nNWAddress=findSignature(nImageBase,nImageSize,"8B4024C1E81FF7D083E001");

    if(nNWAddress!=-1)
    {
         _messageString(MESSAGE_TYPE_WARNING,tr("NW Address found: 0x%1").arg(nNWAddress,0,16));

        // 83 c8
        // AND ->OR
        write_uint8(nNWAddress+9,0xC8);
    }
}
```
        
Discussions about the exception: [https://forum.exetools.com/showthread.php?t=15330](https://forum.exetools.com/showthread.php?t=15330)
