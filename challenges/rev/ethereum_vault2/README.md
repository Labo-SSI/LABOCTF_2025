# WU
kinda similar to first challenge but instead of having plain text strings in gas they are in operations
## Challenge Overview

After decompiling the EVM bytecode, we find a contract that validates a flag. The flag is in the format `LABO{...}` and the contract applies several transformations to check if the content between the braces is correct.

## Initial Analysis

Looking at the disassembled code, we can identify:

1. A check for the length of the input (must be 37 bytes)
2. Validation of the prefix "LABO{" and suffix "}"
3. A series of transformations on the content between the braces
4. A comparison with encoded flag parts

## Step 1: Identify the Encoded Flag Parts and Keys

```solidity
uint256 private constant ENCODED_PART1 = 0x7d88c2d783d583b7d8d8b3d889d3d9d38cd4;
uint256 private constant ENCODED_PART2 = 0x83d9c289d9d387d489d9d5d989c2d5d8c5c2;
uint256 private constant KEY1 = 0x1234567890abcdef1234567890abcdef;
uint256 private constant KEY2 = 0xfedcba0987654321fedcba0987654321;
```

## Step 2: Understand the Transformations

The content is split into two parts:
- `part1`: First 16 bytes
- `part2`: Next 15 bytes

Then four transformation stages are applied:

1. **Bit Rotation**:
   ```solidity
   part1 = ((part1 << 13) | (part1 >> (256 - 13))) & 0xffffffffffffffffffffffffffffffff;
   part2 = ((part2 << 7) | (part2 >> (256 - 7))) & 0xffffffffffffffffffffffffffffff00;
   ```

2. **XOR with Keys**:
   ```solidity
   part1 = part1 ^ KEY1;
   part2 = part2 ^ KEY2;
   ```

3. **Byte Swaps**:
   ```solidity
   part1 = ((part1 & 0xff00ff00ff00ff00ff00ff00ff00ff00) >> 8) | 
           ((part1 & 0x00ff00ff00ff00ff00ff00ff00ff00ff) << 8);
   part2 = ((part2 & 0xff00ff00ff00ff00ff00ff00ff00ff00) >> 8) | 
           ((part2 & 0x00ff00ff00ff00ff00ff00ff00ff00ff) << 8);
   ```

4. **Addition**:
   ```solidity
   part1 = part1 + 0x42424242;
   part2 = part2 + 0x13371337;
   ```

## Step 3: Reverse the Transformations

To recover the original content, we need to reverse each operation in reverse order:

```python
# Step 1: Start with the encoded parts
part1 = 0x7d88c2d783d583b7d8d8b3d889d3d9d38cd4
part2 = 0x83d9c289d9d387d489d9d5d989c2d5d8c5c2

# Step 2: Reverse the addition (Subtract the constants)
part1 = part1 - 0x42424242
part2 = part2 - 0x13371337

# Step 3: Reverse the byte swaps
part1 = ((part1 & 0xff00ff00ff00ff00ff00ff00ff00ff00) >> 8) | ((part1 & 0x00ff00ff00ff00ff00ff00ff00ff00ff) << 8)
part2 = ((part2 & 0xff00ff00ff00ff00ff00ff00ff00ff00) >> 8) | ((part2 & 0x00ff00ff00ff00ff00ff00ff00ff00ff) << 8)

# Step 4: Reverse the XOR (XOR is its own inverse with the same key)
part1 = part1 ^ 0x1234567890abcdef1234567890abcdef
part2 = part2 ^ 0xfedcba0987654321fedcba0987654321

# Step 5: Reverse the rotation
part1 = ((part1 >> 13) | (part1 << (256 - 13))) & 0xffffffffffffffffffffffffffffffff
part2 = ((part2 >> 7) | (part2 << (256 - 7))) & 0xffffffffffffffffffffffffffffff00
```

## Step 4: Converting Back to Bytes

After reversing all transformations, we need to convert `part1` and `part2` back to bytes:

```python
def uint256_to_bytes(n, length):
    return n.to_bytes(length, byteorder='big')

flag_content = uint256_to_bytes(part1, 16) + uint256_to_bytes(part2, 15)
```

## Step 5: Reconstructing the Flag

After converting back to bytes and decoding to ASCII, we get:
```
R3v3rs1ng_EVM_Byt3C0d3_1s_FuN
```

Therefore, the complete flag is:
```
LABO{R3v3rs1ng_EVM_Byt3C0d3_1s_FuN}
```
