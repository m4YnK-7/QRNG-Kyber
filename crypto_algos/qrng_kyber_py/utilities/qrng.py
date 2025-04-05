import qrandom

def get_qrandom():
    """
    Generates three 32-byte blocks of quantum random data using a single API call.

    Returns:
        List[bytes]: A list of three bytes objects, each 32 bytes long.
    """
    # Batch size of 24 32-bit integers yields 96 bytes total (24 * 4 bytes each)
    qr = qrandom.QuantumRandom(batch_size=24)
    
    # Fetch 24 random 32-bit integers
    random_ints = [qr.randint(0, 2**32 - 1) for _ in range(24)]
    
    # Convert each 32-bit integer to 4 bytes (big-endian) and combine them into one bytes object
    all_bytes = b"".join(num.to_bytes(4, byteorder='big') for num in random_ints)
    
    # Split the 96 bytes into three 32-byte blocks
    return [all_bytes[i * 32:(i + 1) * 32] for i in range(3)]

# Example usage:
if __name__ == "__main__":
    blocks = get_qrandom()
    for i, block in enumerate(blocks, 1):
        print(f"Block {i}: {block.hex()}")
