import struct
from typing import List, Tuple

class BlockSecure:
    """
    A custom block cipher with 64-bit blocks and multiple encryption rounds.
    Uses substitution-permutation network (SPN) structure.
    """
    
    # Block size in bytes
    BLOCK_SIZE = 8  # 64 bits
    
    # Number of encryption rounds
    ROUNDS = 4
    
    # S-box for substitution (provides confusion)
    # This is a simple S-box - in practice, you'd want a cryptographically stronger one
    SBOX = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
        0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
        0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
        0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
        0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
        0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
        0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
        0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
        0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
        0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
        0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
        0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
        0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
        0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
        0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ]
    
    # Inverse S-box for decryption
    INV_SBOX = [0] * 256
    for i in range(256):
        INV_SBOX[SBOX[i]] = i
    
    # Permutation table for bit diffusion (provides diffusion)
    # Maps each bit position to a new position
    PBOX = [
        57, 49, 41, 33, 25, 17, 9,  1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7,
        56, 48, 40, 32, 24, 16, 8,  0,
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6
    ]
    
    # Inverse permutation for decryption
    INV_PBOX = [0] * 64
    for i in range(64):
        INV_PBOX[PBOX[i]] = i
    
    def __init__(self, key: bytes):
        """
        Initialize the cipher with a key.
        
        Args:
            key: Encryption key (should be at least 8 bytes)
        """
        if len(key) < 8:
            raise ValueError("Key must be at least 8 bytes")
        
        self.key = key[:8]  # Use first 8 bytes
        self.round_keys = self._generate_round_keys()
    
    def _generate_round_keys(self) -> List[int]:
        """
        Generate round keys from the master key using a simple key schedule.
        
        Returns:
            List of round keys (one per round plus initial)
        """
        master_key = struct.unpack('>Q', self.key)[0]  # Convert to 64-bit integer
        round_keys = []
        
        for i in range(self.ROUNDS + 1):
            # Simple key schedule: rotate and XOR with round constant
            round_key = master_key
            round_key = self._rotate_left_64(round_key, i * 7)
            round_key ^= (i * 0x0123456789ABCDEF) & 0xFFFFFFFFFFFFFFFF
            round_keys.append(round_key)
        
        return round_keys
    
    @staticmethod
    def _rotate_left_64(value: int, shift: int) -> int:
        """Rotate a 64-bit value left by shift bits."""
        shift %= 64
        return ((value << shift) | (value >> (64 - shift))) & 0xFFFFFFFFFFFFFFFF
    
    def _substitute(self, block: int) -> int:
        """Apply S-box substitution to each byte of the block."""
        result = 0
        for i in range(8):
            byte = (block >> (i * 8)) & 0xFF
            result |= self.SBOX[byte] << (i * 8)
        return result
    
    def _inv_substitute(self, block: int) -> int:
        """Apply inverse S-box substitution."""
        result = 0
        for i in range(8):
            byte = (block >> (i * 8)) & 0xFF
            result |= self.INV_SBOX[byte] << (i * 8)
        return result
    
    def _permute(self, block: int) -> int:
        """Apply bit-level permutation."""
        result = 0
        for i in range(64):
            if block & (1 << i):
                result |= 1 << self.PBOX[i]
        return result
    
    def _inv_permute(self, block: int) -> int:
        """Apply inverse bit-level permutation."""
        result = 0
        for i in range(64):
            if block & (1 << i):
                result |= 1 << self.INV_PBOX[i]
        return result
    
    def _encrypt_block(self, block: int) -> int:
        """
        Encrypt a single 64-bit block.
        
        Args:
            block: 64-bit plaintext block
            
        Returns:
            64-bit ciphertext block
        """
        # Initial key whitening
        state = block ^ self.round_keys[0]
        
        # Multiple rounds of substitution-permutation
        for round_num in range(self.ROUNDS):
            # Substitution
            state = self._substitute(state)
            
            # Permutation (skip on last round)
            if round_num < self.ROUNDS - 1:
                state = self._permute(state)
            
            # Add round key
            state ^= self.round_keys[round_num + 1]
        
        return state
    
    def _decrypt_block(self, block: int) -> int:
        """
        Decrypt a single 64-bit block.
        
        Args:
            block: 64-bit ciphertext block
            
        Returns:
            64-bit plaintext block
        """
        state = block
        
        # Reverse the encryption process
        for round_num in range(self.ROUNDS - 1, -1, -1):
            # Remove round key
            state ^= self.round_keys[round_num + 1]
            
            # Inverse permutation (skip on first reverse round)
            if round_num < self.ROUNDS - 1:
                state = self._inv_permute(state)
            
            # Inverse substitution
            state = self._inv_substitute(state)
        
        # Remove initial key whitening
        state ^= self.round_keys[0]
        
        return state
    
    @staticmethod
    def _pad(data: bytes) -> bytes:
        """
        Apply PKCS7 padding to data.
        
        Args:
            data: Data to pad
            
        Returns:
            Padded data
        """
        padding_length = BlockSecure.BLOCK_SIZE - (len(data) % BlockSecure.BLOCK_SIZE)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    @staticmethod
    def _unpad(data: bytes) -> bytes:
        """
        Remove PKCS7 padding from data.
        
        Args:
            data: Padded data
            
        Returns:
            Unpadded data
        """
        if not data:
            raise ValueError("Cannot unpad empty data")
        
        padding_length = data[-1]
        
        "invalid padding when the block size does not meet this parameter"
        if padding_length > BlockSecure.BLOCK_SIZE or padding_length == 0:
            raise ValueError("Invalid padding")
        
        # Verify padding
        for i in range(padding_length):
            if data[-(i + 1)] != padding_length:
                raise ValueError("Invalid padding")
        
        return data[:-padding_length]
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt plaintext using BlockSecure cipher.
        
        Args:
            plaintext: Data to encrypt
            
        Returns:
            Encrypted ciphertext
        """
        # Apply padding
        padded = self._pad(plaintext)
        
        # Encrypt each block
        ciphertext = b''
        for i in range(0, len(padded), self.BLOCK_SIZE):
            block = padded[i:i + self.BLOCK_SIZE]
            block_int = struct.unpack('>Q', block)[0]
            encrypted_block = self._encrypt_block(block_int)
            ciphertext += struct.pack('>Q', encrypted_block)
        
        return ciphertext
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt ciphertext using BlockSecure cipher.
        
        Args:
            ciphertext: Data to decrypt
            
        Returns:
            Decrypted plaintext
        """
        if len(ciphertext) % self.BLOCK_SIZE != 0:
            raise ValueError("Ciphertext length must be multiple of block size")
        
        # Decrypt each block
        plaintext = b''
        for i in range(0, len(ciphertext), self.BLOCK_SIZE):
            block = ciphertext[i:i + self.BLOCK_SIZE]
            block_int = struct.unpack('>Q', block)[0]
            decrypted_block = self._decrypt_block(block_int)
            plaintext += struct.pack('>Q', decrypted_block)
        
        # Remove padding
        return self._unpad(plaintext)


def demo():
    """Demonstrate the BlockSecure cipher with multi-block encryption."""
    print("=" * 70)
    print("BlockSecure Cipher Demonstration")
    print("=" * 70)
    print()
    
    # Setup
    key = b"MySecr3tK3y!"
    cipher = BlockSecure(key)
    
    print(f"Key: {key.decode()}")
    print(f"Block Size: {BlockSecure.BLOCK_SIZE} bytes ({BlockSecure.BLOCK_SIZE * 8} bits)")
    print(f"Number of Rounds: {BlockSecure.ROUNDS}")
    print()
    
    # Multi-block message
    plaintext = b"This is a multi-block message that will be encrypted using our custom BlockSecure cipher!"
    
    print("ENCRYPTION")
    print("-" * 70)
    print(f"Original Message ({len(plaintext)} bytes):")
    print(f"  {plaintext.decode()}")
    print()
    
    # Show blocks
    padded = cipher._pad(plaintext)
    num_blocks = len(padded) // BlockSecure.BLOCK_SIZE
    print(f"After Padding: {len(padded)} bytes ({num_blocks} blocks)")
    for i in range(num_blocks):
        block = padded[i * BlockSecure.BLOCK_SIZE:(i + 1) * BlockSecure.BLOCK_SIZE]
        print(f"  Block {i + 1}: {block.hex()}")
    print()
    
    # Encrypt
    ciphertext = cipher.encrypt(plaintext)
    
    print("Encrypted Ciphertext:")
    print(f"  Hex: {ciphertext.hex()}")
    print()
    
    # Show encrypted blocks
    print("Encrypted Blocks:")
    for i in range(num_blocks):
        block = ciphertext[i * BlockSecure.BLOCK_SIZE:(i + 1) * BlockSecure.BLOCK_SIZE]
        print(f"  Block {i + 1}: {block.hex()}")
    print()
    
    print("DECRYPTION")
    print("-" * 70)
    
    # Decrypt
    decrypted = cipher.decrypt(ciphertext)
    
    print(f"Decrypted Message ({len(decrypted)} bytes):")
    print(f"  {decrypted.decode()}")
    print()
    
    # Verify
    if plaintext == decrypted:
        print(" SUCCESS: Decryption matches original plaintext!")
    else:
        print(" ERROR: Decryption does not match!")
    print()
    
    print("=" * 70)
    
    # Additional test with different message
    print("\nAdditional Test - Short Message")
    print("-" * 70)
    short_msg = b"Hello, World!"
    print(f"Message: {short_msg.decode()}")
    
    encrypted = cipher.encrypt(short_msg)
    print(f"Encrypted: {encrypted.hex()}")
    
    decrypted = cipher.decrypt(encrypted)
    print(f"Decrypted: {decrypted.decode()}")
    print(f"Match: {'✓ Yes' if short_msg == decrypted else '✗ No'}")


if __name__ == "__main__":
    demo()