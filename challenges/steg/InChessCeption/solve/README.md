# InChessCeption

Solution attendue pour la résolution du challenge InChessCeption

## Résolution du challenge

Étapes:

1. Analyse statique de l'image à l'aide de `strings` et `exiftool`
2. Résolution de problèmes d'échecs pour obtenir un mot de passe
3. Extraction d'un fichier secret avec `steghide`
4. Chess Steg, avec l'un de ces outils:
   - <https://github.com/jes/chess-steg>
   - <https://github.com/Alheimsins/chess-steg-cli>
   - <https://incoherency.co.uk/chess-steg/>

### Première étape: analyse statique de l'image

En utilisant `strings` ou `exiftool` sur le fichier, on se rend compte qu'un commentaire est présent:

> Résolvez le puzzle pour trouver le mot de passe qui protège le fichier (notation algébrique française).

Ce qui nous donne deux informations: le fichier caché est protégé par mot de passe, et que le mot de passe de ce fichier est la résolution du problème d'échecs.

### Deuxième étape: résolution du problème

Ce problème est un problème très connu des échecs, imaginé par le grand maître Paul Morphy. C'est un mat en deux qui requiert une grande imagination.

#### Analyse de la position

Le roi noir est dans une position très inconfortable: son roi est piégé entre 2 pions et son fou de cases noires. Depuis l'autre bout de l'échiquier, la tour blanche empêche le pion `a7` de se déplacer.

La position est délicate pour les blancs, qui risquent de faire pat.

Le premier coup qui vient à l'esprit ne rend que la position perdante: après `1. Txa7+`, noir reprendrait avec `1. ... Fxa7` et blanc se retrouverait dans une fin de partie définitivement perdue après `2. bxa7 Rxa7` car le roi blanc ne pourra pas empêcher la promotion du pion noir.

C'est en effet l'étonnant `1. Ta6!` qui est la solution à ce problème puisqu'il force les noirs à prendre la tour avec le pion `b7`, libérant ainsi la place au pion blanc qui viendra délivrer l'échec et mat après la séquence: `1. Ta6 bxa6 2. b7#`

La solution au problème: `1. Ta6 bxa6 2. b7#`

### Troisième étape: Extraction du fichier secret avec `steghide`

On peut découvrir que l'image comporte probablement des données stéganographiques à l'aide de `stegseek`, à l'aide de sa commande `--seed`.

```bash
stegseek --seed chall.jpg
# [i] Found (possible) seed: "a3c9353d"            
#  Plain size: 62.0 Byte(s) (compressed)
#  Encryption Algorithm: rijndael-128
#  Encryption Mode:      cbc
```

L'obtention d'une seed probable indique 99% du temps que des données stéganographiques cachées avec `steghide` se trouvent dans l'image.

Les étapes précédentes faisaient mention d'un mot de passe, et que celui-ci serait la solution au problème d'échecs.

On peut donc extraire des données stéganographiques à l'aide de `steghide`:

```bash
steghide extract -sf chall.jpg -p "1. Ta6 bxa6 2. b7#"
```

Nous obtenons alors le fichier [game.pgn](../sources/game.pgn)

## Indices & informations sur le challenge

Indices step 1:

> Procédez à une analyse statique de l'image. Connaissez-vous les commandes `strings` et `exiftool`?
> Êtes-vous mauvais aux échecs? <https://lichess.org/analysis> et <https://www.chess.com/analysis> devraient vous aider.

Indice step 2:

> Connaissez-vous `steghide`? Un moyen très commun de le détecter est en utilisant `stegseek` avec son option `seed`.

## Flag

`LABOCTF{Checkm8_4n4lysis}`

## Ouverturee, aller plus loin

Pour rendre ce challenge plus compliqué, ou ajouter des étapes:

- Rendre la description plus cryptique, ajouter une énigme
- Utiliser des options
