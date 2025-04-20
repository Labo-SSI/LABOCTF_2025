import argparse

def xor_encrypt_decrypt(input_file, output_file, key):
    try:
        with open(input_file, 'rb') as f:
            data = f.read()
        
        key_bytes = key.encode()
        key_length = len(key_bytes)

        xored_data = bytearray(data[i] ^ key_bytes[i % key_length] for i in range(len(data)))

        with open(output_file, 'wb') as f:
            f.write(xored_data)

        print(f"File processed successfully. Output saved to {output_file}")

    except FileNotFoundError:
        print("Error: Input file not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

def main():

    parser = argparse.ArgumentParser(description="Super malware decoder : User Password Edition")
    parser.add_argument("-k", "--key", type=str, help="Key to decode malware")
    parser.add_argument("-f", "--file", type=str, help="Input file")
    args = parser.parse_args()

    output_file = "malware.decoded"
    
    xor_encrypt_decrypt(args.file, output_file, args.key)

if __name__ == "__main__":
    main()