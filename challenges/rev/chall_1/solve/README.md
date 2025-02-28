# Rev_1

```console
$ ./rev_1 
Go on, enter the password—oh wait, don’t bother. You’ll never guess it anyway.
test

Ahaha did you really think it would be that easy ? Pathetic !
```

Cela ressemble à un crackme, analysons le avec Ghidra.

## Analyse statique

```C
undefined8 main(void)
{
  int strcmp_return_code;
  size_t input_len;
  char user_input [32];
  char *encoded_input;
  int input_len_2;
  
  puts(&INTRO);
  fgets(user_input,26,stdin);
  input_len = strcspn(user_input,"\n");
  input_len_2 = (int)input_len;
  user_input[input_len_2] = '\0';
  xor(user_input,0x69);
  input_len = strlen(user_input);
  encoded_input = (char *)b64_encode(user_input,input_len);
  strcmp_return_code = strcmp(encoded_input,"OjogEjwHChtdCgIIC1haNhkIOjoeWRstFA==");
  if (strcmp_return_code == 0) {
    puts(&WIN);
  }
  else {
    puts(&LOOSE);
  }
  return 0;
}
```

Le programme récupère un input de 26 bytes : `fgets(user_input,26,stdin);`.

Il remplace le `\n` par `\00` : `user_input[input_len_2] = '\0';`.

Le xor pas `0x69` : `xor(user_input,0x69);`.

Puis l'encode en base64 : `encoded_input = (char *)b64_encode(user_input,input_len);`.

Enfin il le compare à ce qui semble être le mot de passe : `strcmp(encoded_input,"OjogEjwHChtdCgIIC1haNhkIOjoeWRstFA==");`.

Si l'input une fois xoré, puis encodé en base64 correspond à `OjogEjwHChtdCgIIC1haNhkIOjoeWRstFA==`, le message `WIN` est affiché :

```
"\nImpossible",E2h,80h,A6h," Comment as-tu r",C3h,A9h,"ussi ",C3h,A0h," le craquer ?! Ce n'est pas possible !\nHmph",E2h,80h,A6h," tr",C3h,A8h,"s bien, prends ton pr",C3h,A9h,"cieux flag et fiche le camp !"
```

Tentons de retrouver le mot de passe qui correspond à `OjogEjwHChtdCgIIC1haNhkIOjoeWRstFA==`.

## Exploit

`OjogEjwHChtdCgIIC1haNhkIOjoeWRstFA==` est en base64, décodons le :

```python3
>>> base64.b64decode("OjogEjwHChtdCgIIC1haNhkIOjoeWRstFA==")
b':: \x12<\x07\n\x1b]\n\x02\x08\x0bXZ6\x19\x08::\x1eY\x1b-\x14'
```

Le contenu semble incompréhensible, mais nous avons vu plus tôt que l'input est asser xoré par `0x69`. Tentons de le décoder :

```python3
>>> base64.b64decode("OjogEjwHChtdCgIIC1haNhkIOjoeWRstFA==")
b':: \x12<\x07\n\x1b]\n\x02\x08\x0bXZ6\x19\x08::\x1eY\x1b-\x14'

>>> [ chr(i^0x69) for i in _ ] 
['S', 'S', 'I', '{', 'U', 'n', 'c', 'r', '4', 'c', 'k', 'a', 'b', '1', '3', '_', 'p', 'a', 'S', 'S', 'w', '0', 'r', 'D', '}']

>>> "".join(_)
'SSI{Uncr4ckab13_paSSw0rD}'
```

Nous avons le flag : `SSI{Uncr4ckab13_paSSw0rD}`.
