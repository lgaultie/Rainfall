```
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

`
char *gets(char *s)
gets() reads a line from stdin into the buffer pointed to by s until either a terminating newline or EOF, which it replaces with a null byte (aq\0aq). No check for buffer overrun is performed (see BUGS below).` </br>
`[...]`</br>
`Bugs`</br>
`Never use gets(). Because it is impossible to tell without knowing the data in advance how many characters gets() will read, and because gets() will continue to store characters past the end of the buffer, it is extremely dangerous to use. It has been used to break computer security.
`</br>
https://linux.die.net/man/3/gets

`
The basic problem is that the function doesn't know how big the buffer is, so it continues reading until it finds a newline or encounters EOF, and may overflow the bounds of the buffer it was given.
`</br>
https://stackoverflow.com/questions/1694036/why-is-the-gets-function-so-dangerous-that-it-should-not-be-used

Let's do some documentation on buffer overflows and find how to perform a `buffer overflow attack`.