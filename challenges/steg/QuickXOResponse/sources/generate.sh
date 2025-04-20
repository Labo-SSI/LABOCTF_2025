#!/bin/bash

for file in "fake.txt" "flag.txt";
do
    qrencode -o "$file.png" -l L -m 0 -r "$file"
done

python xor.py

cp key.png ../key.png
cp fake.txt.png ../fake.png
