import struct

def rotr(value, bits):
    return ((value >> bits) | (value << (32 - bits))) & 0xFFFFFFFF

def sigma_0(x):
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)

def sigma_1(x):
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)

def choice(e, f, g):
    return (e & f) ^ (~e & g)

def majority(a, b, c):
    return (a & b) ^ (a & c) ^ (b & c)

def sigma_1_custom(e):
    return rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)

def sigma_0_custom(a):
    return rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)

def sha256_file(file_path):
    # Initialize hash values h0 to h7 (first 32 bits of the fractional parts of the square roots of the first 8 primes)
    H = [
        0x6a09e667,  # h0
        0xbb67ae85,  # h1
        0x3c6ef372,  # h2
        0xa54ff53a,  # h3
        0x510e527f,  # h4
        0x9b05688c,  # h5
        0x1f83d9ab,  # h6
        0x5be0cd19   # h7
    ]
    
    # Initialize the K constants (first 32 bits of the fractional parts of the cube roots of the first 64 primes)
    K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]

    # Step 1: Read the file content as binary data
    with open(file_path, 'rb') as file:
        message_bytes = file.read()

    # Step 2: Convert message bytes to binary string
    binary_message = ''.join(f'{byte:08b}' for byte in message_bytes)

    # Step 3: Append a single '1'
    binary_message += '1'

    # Step 4: Calculate original length in bits (64-bit big-endian integer)
    original_length_bits = len(message_bytes) * 8  # Original length in bits (before padding)
    binary_length = f'{original_length_bits:064b}'

    # Step 5: Add padding zeros until the message length is congruent to 448 mod 512
    padding_needed = (448 - (len(binary_message) % 512)) % 512
    binary_message += '0' * padding_needed

    # Step 6: Append the 64-bit message length
    binary_message += binary_length

    # Step 7: Break the message into 512-bit chunks
    chunks = [binary_message[i:i+512] for i in range(0, len(binary_message), 512)]

    for chunk in chunks:
        # Step 8: Create a 64-entry message schedule array w[0..63] of 32-bit words
        w = [0] * 64

        # Step 9: Copy chunk into 1st 16 words w[0..15] of the message schedule array
        for i in range(16):
            w[i] = int(chunk[i * 32:(i + 1) * 32], 2)

        # Step 10: Compute w[i] for i = 16 to 63
        for i in range(16, 64):
            w[i] = (sigma_1(w[i - 2]) + w[i - 7] + sigma_0(w[i - 15]) + w[i - 16]) & 0xFFFFFFFF

        # Initialize working variables to current hash value
        a = H[0]
        b = H[1]
        c = H[2]
        d = H[3]
        e = H[4]
        f = H[5]
        g = H[6]
        h = H[7]

        # Hash computation loop
        for i in range(64):
            # Compute Temp1 and Temp2
            Σ1 = sigma_1_custom(e)
            choice_val = choice(e, f, g)
            Temp1 = h + Σ1 + choice_val + K[i] + w[i]
            Σ0 = sigma_0_custom(a)
            majority_val = majority(a, b, c)
            Temp2 = Σ0 + majority_val

            # Update working variables
            h = g
            g = f
            f = e
            e = (d + Temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (Temp1 + Temp2) & 0xFFFFFFFF

        # Update the hash values after processing each chunk
        H[0] = (H[0] + a) & 0xFFFFFFFF
        H[1] = (H[1] + b) & 0xFFFFFFFF
        H[2] = (H[2] + c) & 0xFFFFFFFF
        H[3] = (H[3] + d) & 0xFFFFFFFF
        H[4] = (H[4] + e) & 0xFFFFFFFF
        H[5] = (H[5] + f) & 0xFFFFFFFF
        H[6] = (H[6] + g) & 0xFFFFFFFF
        H[7] = (H[7] + h) & 0xFFFFFFFF

    # Generate the final SHA-256 digest
    final_hash = ''.join(f'{h:08x}' for h in H)
    return final_hash


# Example usage
if __name__ == "__main__":
    file_path = input("Digite o caminho do arquivo para gerar o hash SHA-256: ")
    try:
        hash_result = sha256_file(file_path)
        print(f"SHA-256 do arquivo: {hash_result}")
    except FileNotFoundError:
        print("Arquivo não encontrado. Verifique o caminho e tente novamente.")
    except Exception as e:
        print(f"Ocorreu um erro: {str(e)}")
