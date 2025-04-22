# Quantum Emulator

## Analyse initiale

En exécutant le binaire, nous sommes accueillis par une interface interactive:

```
╔═══════════════════════════════════════════════════════════╗
║                  QUANTUM EMULATOR v2.0                    ║
╚═══════════════════════════════════════════════════════════╝

Welcome to the Quantum Laboratory Emulator!
This system simulates a 4-qubit quantum computer.
Your mission: Find the correct sequence of quantum gates to
generate a specific entangled state and unlock the flag.

Available gates:
  • X gate (bit flip)
  • Y gate (bit+phase flip)
  • Z gate (phase flip)
  • H gate (Hadamard/superposition)
  • CNOT gate (controlled-NOT)
  • SWAP gate (swap qubits)
```

Le programme nous permet d'appliquer différentes opérations quantiques et d'observer l'état résultant du système.

## Rétro-ingénierie du binaire

En ouvrant le binaire dans Ghidra/IDA, on peux identifier plusieurs éléments clés:

1. Une classe `QuantumEmulator` qui gère l'état du système
2. Un vecteur d'état quantique (`quantum_state`)
3. Un historique d'opérations (`operation_history`)
4. Une fonction `check_sequence()` qui vérifie si certaines conditions sont remplies
5. Un tableau `encrypted_flag` contenant le flag chiffré

L'analyse de la fonction `check_sequence()` révèle qu'elle vérifie si les 5 dernières opérations correspondent à l'une des trois séquences valides:

```cpp
// Solution 1: H0 -> H2 -> CNOT 0,1 -> CNOT 2,3 -> Z3
if (operation_history[n-5] == 40 && 
    operation_history[n-4] == 42 && 
    operation_history[n-3] == 501 && 
    operation_history[n-2] == 523 && 
    operation_history[n-1] == 33) {
    return true;
}

// Solution 2: H2 -> H0 -> CNOT 0,1 -> CNOT 2,3 -> Z3
if (operation_history[n-5] == 42 && 
    operation_history[n-4] == 40 && 
    operation_history[n-3] == 501 && 
    operation_history[n-2] == 523 && 
    operation_history[n-1] == 33) {
    return true;
}

// Solution 3: H0 -> H2 -> CNOT 2,3 -> CNOT 0,1 -> Z3
if (operation_history[n-5] == 40 && 
    operation_history[n-4] == 42 && 
    operation_history[n-3] == 523 && 
    operation_history[n-2] == 501 && 
    operation_history[n-1] == 33) {
    return true;
}
```

Chaque opération est codée comme suit:
- H0 = 40 (Hadamard sur qubit 0)
- H2 = 42 (Hadamard sur qubit 2)
- CNOT 0,1 = 501 (CNOT avec contrôle 0, cible 1)
- CNOT 2,3 = 523 (CNOT avec contrôle 2, cible 3)
- Z3 = 33 (Z sur qubit 3)

## Déchiffrement du flag

Le flag est stocké sous forme chiffrée dans le tableau `encrypted_flag`, et il est déchiffré avec une clé XOR de 42 (0x2A) lorsque la séquence correcte est appliquée:
(donc soit tu recraft le flag en statique, soit tu applique l'opperation quantique pour obtenir le flag)

```cpp
const unsigned char key = 42;  // 0x2A
std::cout << "Flag: ";
for (size_t i = 0; i < sizeof(encrypted_flag); i++) {
    std::cout << static_cast<char>(encrypted_flag[i] ^ key);
}
```

## Solution

Pour résoudre le challenge, nous devons appliquer l'une des trois séquences valides. Utilisons la deuxième solution:

1. Appliquer Hadamard (H) sur qubit 2
2. Appliquer Hadamard (H) sur qubit 0
3. Appliquer CNOT avec qubit 0 comme contrôle et qubit 1 comme cible
4. Appliquer CNOT avec qubit 2 comme contrôle et qubit 3 comme cible
5. Appliquer Z sur qubit 3
6. Mesurer l'état

En analysant toutes ces fonctions, on peut déduire le schéma de codage :
Pour les portes à un qubit (H, X, Y, Z) :
Formule : (type_porte × 10) + indice_qubit
```

Type de porte :

X gate : 1
Y gate : 2
Z gate : 3
H gate : 4



Donc :

H sur qubit 0 : 4×10 + 0 = 40
H sur qubit 2 : 4×10 + 2 = 42
Z sur qubit 3 : 3×10 + 3 = 33

Pour les portes à deux qubits (CNOT, SWAP) :
Formule : (type_porte × 100) + (qubit1 × 10) + qubit2

Type de porte :

CNOT : 5
SWAP : 6



Donc :

CNOT avec contrôle 0, cible 1 : 5×100 + 0×10 + 1 = 501
CNOT avec contrôle 2, cible 3 : 5×100 + 2×10 + 3 = 523
```

Voici la séquence de commandes à entrer:

```
H 2
H 0
CNOT 0 1
CNOT 2 3
Z 3
MEASURE
```

`LABO{qu4ntum_enT4ngl3m3nt_m4st3r}`

## bonus

L'état final est:
```
1/2 (|0000⟩ + |0011⟩ + |1100⟩ - |1111⟩)
```

## solve script

```python
from pwn import *

# Connexion au challenge (localement ou à distance)
p = process('./quantum_emulator')

def apply_gate(gate, *args):
    p.sendlineafter('EXIT): ', gate)
    for arg in args:
        p.sendlineafter('): ', str(arg))

# Attendre l'initialisation
p.recvuntil('display_state')

# Appliquer la séquence correcte
apply_gate('H', 2)
apply_gate('H', 0)
apply_gate('CNOT', 0, 1)
apply_gate('CNOT', 2, 3)
apply_gate('Z', 3)

# Mesurer pour obtenir le flag
p.sendlineafter('EXIT): ', 'MEASURE')

# Récupérer le flag
p.recvuntil('EXIT):')
flag = p.recvline().strip()
print(f"Flag: {flag.decode()}")

p.close()
```
