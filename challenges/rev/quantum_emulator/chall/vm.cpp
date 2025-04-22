// NE SURTOUT PAS DEPLOYER EN PUBLIC

#include <iostream>
#include <complex>
#include <vector>
#include <cmath>
#include <ctime>
#include <cstdlib>
#include <iomanip>
#include <string>
#include <random>
#include <chrono>
#include <thread>

// Define complex number type for easier use
typedef std::complex<double> complex;

// Number of qubits in our system
const int NUM_QUBITS = 4;
const int STATE_SIZE = 1 << NUM_QUBITS; // 2^NUM_QUBITS

const unsigned char encrypted_flag[] = {
    0x66, 0x6B, 0x68, 0x65, 0x51, 0x57, 0x5F, 0x1E, 0x44, 0x5E, 0x5F, 0x47, 0x75, 0x4F, 0x44,
    0x7E, 0x1E, 0x44, 0x4D, 0x46, 0x19, 0x47, 0x19, 0x44, 0x5E, 0x75, 0x47, 0x1E, 0x59, 0x5E,
    0x19, 0x58, 0x57
};

// Class to encapsulate our quantum emulator
class QuantumEmulator {
private:
    // Main quantum state
    std::vector<complex> quantum_state;
    
    // Track which operations have been applied
    std::vector<int> operation_history;
    
    // Random number generator for scientific outputs
    std::mt19937 rng;
    std::uniform_real_distribution<double> unif;

public:
    QuantumEmulator() : 
        quantum_state(STATE_SIZE), 
        unif(0.0, 1.0) {
        
        // Seed RNG
        rng.seed(static_cast<unsigned int>(
            std::chrono::steady_clock::now().time_since_epoch().count()
        ));
        
        // Initialize state to |0000>
        initialize_state();
    }
    
    // Function to initialize our quantum state to |0000>
    void initialize_state() {
        for (int i = 0; i < STATE_SIZE; i++) {
            quantum_state[i] = complex(0.0, 0.0);
        }
        quantum_state[0] = complex(1.0, 0.0); // |0000> = 1, everything else = 0
        
        // Clear operation history on reset
        operation_history.clear();
    }
    
    // Function to display state with lots of scientific output
    void display_state() {
        std::cout << "\n====== QUANTUM STATE VECTOR ANALYSIS ======\n";
        std::cout << "Planck constant ħ = 1.0545718e-34 J⋅s\n";
        std::cout << "System decoherence time: " << std::fixed << std::setprecision(9) 
                  << 50.0 + unif(rng) * 100.0 << " μs\n";
        std::cout << "Quantum tunneling probability: " << std::scientific << std::setprecision(6) 
                  << 1e-10 + unif(rng) * 1e-9 << "\n";
        
        // Calculate fake fidelity metric
        double fidelity = 0.98 + unif(rng) * 0.02;
        std::cout << "State fidelity: " << std::fixed << std::setprecision(8) << fidelity << "\n\n";
        
        // Display the actual state vector with noise
        for (int i = 0; i < STATE_SIZE; i++) {
            // Convert i to binary representation for basis state
            std::string basis = "";
            for (int j = NUM_QUBITS - 1; j >= 0; j--) {
                basis += ((i >> j) & 1) ? "1" : "0";
            }
            
            // Display complex amplitude with scientific notation
            std::cout << "|" << basis << "> : " 
                      << std::scientific << std::setprecision(8) 
                      << quantum_state[i].real() << " + " 
                      << quantum_state[i].imag() << "i   ";
            
            // Calculate probability with fake quantum noise
            double prob = std::norm(quantum_state[i]) * 100.0;
            std::cout << "P = " << std::fixed << std::setprecision(6) << prob << "% ± " 
                      << std::setprecision(10) << unif(rng) * 1e-8 << "\n";
        }
        
        // More fake scientific output
        std::cout << "\nQuantum coherence factor: " << std::scientific << std::setprecision(6) 
                  << 1.0 - unif(rng) * 0.01 << "\n";
        std::cout << "Von Neumann entropy: " << std::fixed << std::setprecision(6) 
                  << -unif(rng) * 0.1 << " bits\n";
        std::cout << "Quantum Fisher information: " << std::scientific << std::setprecision(4)
                  << 10.0 + unif(rng) * 5.0 << "\n";
        std::cout << "Wigner function negativity: " << std::fixed << std::setprecision(6)
                  << unif(rng) * 0.2 << "\n";
        std::cout << "===========================================\n";
    }
    
    // X gate (NOT) on a specific qubit
    void apply_X(int qubit) {
        if (qubit < 0 || qubit >= NUM_QUBITS) {
            std::cout << "Error: Invalid qubit index!\n";
            return;
        }
        
        int mask = 1 << qubit;
        
        std::vector<complex> new_state = quantum_state;
        for (int i = 0; i < STATE_SIZE; i++) {
            int j = i ^ mask; // Flip the bit at the qubit position
            new_state[j] = quantum_state[i];
        }
        quantum_state = new_state;
        
        // Record this operation (code 1)
        operation_history.push_back(1 * 10 + qubit);
        
        std::cout << "Applied X (NOT) gate to qubit " << qubit << "\n";
        std::cout << "X-gate unitary matrix applied with fidelity: " 
                  << std::fixed << std::setprecision(10) << 0.999999 + unif(rng) * 0.000001 << "\n";
    }
    
    // Z gate on a specific qubit
    void apply_Z(int qubit) {
        if (qubit < 0 || qubit >= NUM_QUBITS) {
            std::cout << "Error: Invalid qubit index!\n";
            return;
        }
        
        int mask = 1 << qubit;
        
        for (int i = 0; i < STATE_SIZE; i++) {
            if (i & mask) { // If the qubit is |1>
                quantum_state[i] *= -1.0; // Multiply by -1
            }
        }
        
        // Record this operation (code 3)
        operation_history.push_back(3 * 10 + qubit);
        
        std::cout << "Applied Z gate to qubit " << qubit << "\n";
        std::cout << "Phase rotation completed with Z-gate precision: " 
                  << std::scientific << std::setprecision(12) << 1.0 - unif(rng) * 1e-11 << "\n";
    }
    
    // Y gate on a specific qubit
    void apply_Y(int qubit) {
        if (qubit < 0 || qubit >= NUM_QUBITS) {
            std::cout << "Error: Invalid qubit index!\n";
            return;
        }
        
        int mask = 1 << qubit;
        
        std::vector<complex> new_state = quantum_state;
        for (int i = 0; i < STATE_SIZE; i++) {
            int j = i ^ mask; // Flip the bit at the qubit position
            if (i & mask) {
                new_state[j] = quantum_state[i] * complex(0, -1);
            } else {
                new_state[j] = quantum_state[i] * complex(0, 1);
            }
        }
        quantum_state = new_state;
        
        // Record this operation (code 2)
        operation_history.push_back(2 * 10 + qubit);
        
        std::cout << "Applied Y gate to qubit " << qubit << "\n";
        std::cout << "Complex phase rotation applied with Y-gate accuracy: " 
                  << std::fixed << std::setprecision(12) << 0.9999999999 + unif(rng) * 0.0000000001 << "\n";
    }
    
    // Hadamard gate on a specific qubit
    void apply_H(int qubit) {
        if (qubit < 0 || qubit >= NUM_QUBITS) {
            std::cout << "Error: Invalid qubit index!\n";
            return;
        }
        
        int mask = 1 << qubit;
        
        std::vector<complex> new_state = quantum_state;
        
        for (int i = 0; i < STATE_SIZE; i++) {
            int j = i ^ mask; // State with the qubit flipped
            
            complex a = quantum_state[i];
            complex b = quantum_state[j];
            
            // Apply the Hadamard transformation
            new_state[i] = (a + b) / std::sqrt(2.0);
            new_state[j] = (a - b) / std::sqrt(2.0);
        }
        
        quantum_state = new_state;
        
        // Record this operation (code 4)
        operation_history.push_back(4 * 10 + qubit);
        
        std::cout << "Applied H (Hadamard) gate to qubit " << qubit << "\n";
        std::cout << "Superposition created with quantum interference coefficient: " 
                  << std::scientific << std::setprecision(8) << std::sqrt(2.0) - unif(rng) * 1e-10 << "\n";
    }
    
    // CNOT gate with control and target qubits
    void apply_CNOT(int control, int target) {
        if (control < 0 || control >= NUM_QUBITS || 
            target < 0 || target >= NUM_QUBITS || 
            control == target) {
            std::cout << "Error: Invalid qubit indices!\n";
            return;
        }
        
        int control_mask = 1 << control;
        int target_mask = 1 << target;
        
        std::vector<complex> new_state = quantum_state;
        
        for (int i = 0; i < STATE_SIZE; i++) {
            if (i & control_mask) { // Only if control qubit is |1>
                int j = i ^ target_mask; // Flip the target qubit
                new_state[j] = quantum_state[i];
                new_state[i] = complex(0.0, 0.0);
            }
        }
        
        quantum_state = new_state;
        
        // Record this operation (code 5)
        operation_history.push_back(5 * 100 + control * 10 + target);
        
        std::cout << "Applied CNOT gate with control qubit " << control << " and target qubit " << target << "\n";
        std::cout << "Quantum entanglement established with Bell state purity: " 
                  << std::fixed << std::setprecision(10) << 0.999 + unif(rng) * 0.001 << "\n";
    }
    
    // SWAP gate between two qubits
    void apply_SWAP(int qubit1, int qubit2) {
        if (qubit1 < 0 || qubit1 >= NUM_QUBITS || 
            qubit2 < 0 || qubit2 >= NUM_QUBITS || 
            qubit1 == qubit2) {
            std::cout << "Error: Invalid qubit indices!\n";
            return;
        }
        
        if (qubit1 > qubit2) {
            std::swap(qubit1, qubit2);
        }
        
        int mask1 = 1 << qubit1;
        int mask2 = 1 << qubit2;
        
        std::vector<complex> new_state = quantum_state;
        
        for (int i = 0; i < STATE_SIZE; i++) {
            // Only need to swap if exactly one of the bits is set
            if ((i & mask1) && !(i & mask2)) {
                // Bit1 is 1, bit2 is 0, swap them
                int j = (i & ~mask1) | mask2;
                new_state[j] = quantum_state[i];
                new_state[i] = complex(0.0, 0.0);
            } else if (!(i & mask1) && (i & mask2)) {
                // Bit1 is 0, bit2 is 1, swap them
                int j = (i & ~mask2) | mask1;
                new_state[j] = quantum_state[i];
                new_state[i] = complex(0.0, 0.0);
            }
        }
        
        quantum_state = new_state;
        
        // Record this operation (code 6)
        operation_history.push_back(6 * 100 + qubit1 * 10 + qubit2);
        
        std::cout << "Applied SWAP gate between qubits " << qubit1 << " and " << qubit2 << "\n";
        std::cout << "Quantum information transposition completed with swap fidelity: " 
                  << std::fixed << std::setprecision(8) << 0.9999 + unif(rng) * 0.0001 << "\n";
    }
    
    // The key verification function - checks if the correct sequence was applied
    bool check_sequence() {
        // Need at least 5 operations
        if (operation_history.size() < 5) {
            return false;
        }
        
        // The solution sequence codes:
        // 40 = H on qubit 0
        // 42 = H on qubit 2
        // 501 = CNOT with control 0, target 1
        // 523 = CNOT with control 2, target 3
        // 33 = Z on qubit 3
        
        // Check if the last 5 operations match one of our solutions
        if (operation_history.size() >= 5) {
            int n = operation_history.size();
            
            // Solution 1: H0 -> H2 -> CNOT 0,1 -> CNOT 2,3 -> Z3
            if (operation_history[n-5] == 40 && 
                operation_history[n-4] == 42 && 
                operation_history[n-3] == 501 && 
                operation_history[n-2] == 523 && 
                operation_history[n-1] == 33) {
                return true;
            }
            
            // Solution 2: H2 -> H0 -> CNOT 0,1 -> CNOT 2,3 -> Z3 (order of H gates swapped)
            if (operation_history[n-5] == 42 && 
                operation_history[n-4] == 40 && 
                operation_history[n-3] == 501 && 
                operation_history[n-2] == 523 && 
                operation_history[n-1] == 33) {
                return true;
            }
            
            // Solution 3: A more complex but equivalent circuit
            // H0 -> H2 -> CNOT 2,3 -> CNOT 0,1 -> Z3 (order of CNOTs swapped)
            if (operation_history[n-5] == 40 && 
                operation_history[n-4] == 42 && 
                operation_history[n-3] == 523 && 
                operation_history[n-2] == 501 && 
                operation_history[n-1] == 33) {
                return true;
            }
        }
        
        return false;
    }
    
    // Try to get the flag by checking if the sequence is correct
    void try_get_flag() {
        bool success = check_sequence();
        
        std::cout << "\nPerforming quantum measurement...\n";
        for (int i = 0; i < 8; i++) {
            std::cout << "." << std::flush;
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        std::cout << "\n";
        
        if (success) {
            std::cout << "\n🌟 QUANTUM STATE VERIFIED! 🌟\n";
            std::cout << "You've discovered the correct quantum circuit configuration.\n";
            
            // Simulate intense computation
            std::cout << "Extracting quantum key from operation history...\n";
            for (int i = 0; i < 10; i++) {
                std::cout << "." << std::flush;
                std::this_thread::sleep_for(std::chrono::milliseconds(300));
            }
            std::cout << "\n";
            
            // La clé de déchiffrement est fixée à 42 (0x2A)
            // Pour une séquence valide, nous utilisons toujours cette clé
            const unsigned char key = 42;
            
            // Déchiffrer et afficher le flag
            std::cout << "Flag: ";
            for (size_t i = 0; i < sizeof(encrypted_flag); i++) {
                std::cout << static_cast<char>(encrypted_flag[i] ^ key);
            }
            std::cout << std::endl;
        } else {
            std::cout << "\n❌ Quantum state verification failed! ❌\n";
            std::cout << "The system does not detect the required quantum signature.\n";
            std::cout << "Try a different sequence of quantum operations.\n";
            
            // Give a subtle hint for players who are close
            if (operation_history.size() >= 5) {
                int n = operation_history.size();
                int close_count = 0;
                
                // Count how many of the last 5 operations are part of a solution
                if (operation_history[n-5] == 40 || operation_history[n-5] == 42) close_count++;
                if (operation_history[n-4] == 40 || operation_history[n-4] == 42) close_count++;
                if (operation_history[n-3] == 501 || operation_history[n-3] == 523) close_count++;
                if (operation_history[n-2] == 501 || operation_history[n-2] == 523) close_count++;
                if (operation_history[n-1] == 33) close_count++;
                
                if (close_count >= 3) {
                    std::cout << "\n[System diagnostic]: State analysis indicates partial quantum alignment.\n";
                    std::cout << "Multiple entangled qubit pairs detected. Verifying quantum signatures...\n";
                }
            }
        }
    }
};

// Main function
int main() {
    // Fancy ASCII art header
    std::cout << "╔═══════════════════════════════════════════════════════════╗\n";
    std::cout << "║                  YNOV QUANTUM EMULATOR                    ║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════╝\n\n";
    
    std::cout << "Welcome to the Quantum Laboratory Emulator!\n";
    std::cout << "This system simulates a " << NUM_QUBITS << "-qubit quantum computer.\n";
    std::cout << "Your mission: Find the correct sequence of quantum gates to\n";
    std::cout << "generate a specific entangled state and unlock the flag.\n\n";
    
    std::cout << "Available gates:\n";
    std::cout << "  • X gate (bit flip)\n";
    std::cout << "  • Y gate (bit+phase flip)\n";
    std::cout << "  • Z gate (phase flip)\n";
    std::cout << "  • H gate (Hadamard/superposition)\n";
    std::cout << "  • CNOT gate (controlled-NOT)\n";
    std::cout << "  • SWAP gate (swap qubits)\n\n";
    
    std::cout << "Initializing quantum system...\n";
    for (int i = 0; i < 5; i++) {
        std::cout << "." << std::flush;
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }
    std::cout << "\n";
    
    QuantumEmulator emulator;
    emulator.display_state();
    
    std::string command;
    while (true) {
        std::cout << "\nEnter a quantum gate command (X, Y, Z, H, CNOT, SWAP, MEASURE, RESET, EXIT): ";
        std::cin >> command;
        
        if (command == "EXIT") {
            std::cout << "Shutting down quantum emulator...\n";
            break;
        } else if (command == "RESET") {
            std::cout << "Resetting quantum system to initial state |0000>...\n";
            emulator.initialize_state();
            emulator.display_state();
        } else if (command == "X") {
            int qubit;
            std::cout << "Enter qubit (0-" << NUM_QUBITS-1 << "): ";
            std::cin >> qubit;
            emulator.apply_X(qubit);
            emulator.display_state();
        } else if (command == "Y") {
            int qubit;
            std::cout << "Enter qubit (0-" << NUM_QUBITS-1 << "): ";
            std::cin >> qubit;
            emulator.apply_Y(qubit);
            emulator.display_state();
        } else if (command == "Z") {
            int qubit;
            std::cout << "Enter qubit (0-" << NUM_QUBITS-1 << "): ";
            std::cin >> qubit;
            emulator.apply_Z(qubit);
            emulator.display_state();
        } else if (command == "H") {
            int qubit;
            std::cout << "Enter qubit (0-" << NUM_QUBITS-1 << "): ";
            std::cin >> qubit;
            emulator.apply_H(qubit);
            emulator.display_state();
        } else if (command == "CNOT") {
            int control, target;
            std::cout << "Enter control qubit (0-" << NUM_QUBITS-1 << "): ";
            std::cin >> control;
            std::cout << "Enter target qubit (0-" << NUM_QUBITS-1 << "): ";
            std::cin >> target;
            emulator.apply_CNOT(control, target);
            emulator.display_state();
        } else if (command == "SWAP") {
            int qubit1, qubit2;
            std::cout << "Enter first qubit (0-" << NUM_QUBITS-1 << "): ";
            std::cin >> qubit1;
            std::cout << "Enter second qubit (0-" << NUM_QUBITS-1 << "): ";
            std::cin >> qubit2;
            emulator.apply_SWAP(qubit1, qubit2);
            emulator.display_state();
        } else if (command == "MEASURE") {
            emulator.try_get_flag();
        } else {
            std::cout << "Error: Unknown quantum operation!\n";
        }
    }
    
    return 0;
}
