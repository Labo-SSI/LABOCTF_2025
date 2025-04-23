// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

contract FlagChecker {
    // Constants for the flag check
    bytes4 private constant PREFIX = 0x4c41424f; // "LABO" in hex
    bytes1 private constant LEFT_BRACE = 0x7b; // "{" in hex
    bytes1 private constant RIGHT_BRACE = 0x7d; // "}" in hex
    
    // These will hold the encoded flag parts - each operation can be reversed
    uint256 private constant ENCODED_PART1 = 0x7d88c2d783d583b7d8d8b3d889d3d9d38cd4; // First part of encoded flag
    uint256 private constant ENCODED_PART2 = 0x83d9c289d9d387d489d9d5d989c2d5d8c5c2; // Second part of encoded flag
    
    // Symmetric keys for encoding/decoding
    uint256 private constant KEY1 = 0x1234567890abcdef1234567890abcdef;
    uint256 private constant KEY2 = 0xfedcba0987654321fedcba0987654321;
    
    // Main validation function
    function checkFlag(bytes calldata input) external pure returns (bool) {
        // Basic checks
        if (input.length != 37) return false;
        
        // Check prefix "LABO{"
        if (bytes4(input[0]) | (bytes4(input[1]) << 8) | (bytes4(input[2]) << 16) | (bytes4(input[3]) << 24) != PREFIX) 
            return false;
        if (input[4] != LEFT_BRACE) return false;
        
        // Check suffix "}"
        if (input[input.length - 1] != RIGHT_BRACE) return false;
        
        // Extract the content between LABO{ and }
        bytes memory content = new bytes(input.length - 6);
        for (uint i = 0; i < content.length; i++) {
            content[i] = input[i + 5];
        }
        
        // The rest of the check is fully reversible
        return validateFlagContent(content);
    }
    
    // This function validates the content between LABO{ and }
    function validateFlagContent(bytes memory content) private pure returns (bool) {
        uint256 part1;
        uint256 part2;
        
        // Extract bytes from content and pack them into uint256 values
        assembly {
            // Load first 16 bytes (bytes 0-15) into part1
            part1 := mload(add(add(content, 32), 0))
            
            // Load next 15 bytes (bytes 16-30) into part2
            part2 := mload(add(add(content, 32), 16))
            
            // Mask out any extra bytes for part2 (we only want 15 bytes)
            part2 := and(part2, 0xffffffffffffffffffffffffffffff000000000000000000000000)
        }
        
        // Apply series of reversible transformations
        // All these operations can be deterministically reversed
        
        // Stage 1: Rotate bits
        part1 = ((part1 << 13) | (part1 >> (256 - 13))) & 0xffffffffffffffffffffffffffffffff;
        part2 = ((part2 << 7) | (part2 >> (256 - 7))) & 0xffffffffffffffffffffffffffffff00;
        
        // Stage 2: XOR operations
        part1 = part1 ^ KEY1;
        part2 = part2 ^ KEY2;
        
        // Stage 3: Byte swaps (pairs of bytes swap positions)
        part1 = ((part1 & 0xff00ff00ff00ff00ff00ff00ff00ff00) >> 8) | 
                ((part1 & 0x00ff00ff00ff00ff00ff00ff00ff00ff) << 8);
        part2 = ((part2 & 0xff00ff00ff00ff00ff00ff00ff00ff00) >> 8) | 
                ((part2 & 0x00ff00ff00ff00ff00ff00ff00ff00ff) << 8);
        
        // Stage 4: Add constants
        part1 = part1 + 0x42424242;
        part2 = part2 + 0x13371337;
        
        // Compare with the encoded flag parts
        return (part1 == ENCODED_PART1 && part2 == ENCODED_PART2);
    }
    
    // Helper function for anyone who wants a hint
    function getHint() external pure returns (string memory) {
        return "Each transformation is reversible - try working backwards!";
    }
}
