#!/bin/bash

# npm i -g chess-steg-cli
chess-steg -s "$(cat flag.txt)" > game.pgn
echo " { Chess Steganography go brrrrrrrrrr }" >> game.pgn
steghide embed -ef game.pgn -cf board.jpg -p "$(cat solution.txt)" -sf chall.jpg
exiftool -Comment="Résolvez le puzzle pour trouver le mot de passe qui protège le fichier (notation algébrique française)." chall.jpg
cp chall.jpg ..
