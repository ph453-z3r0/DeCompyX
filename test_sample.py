#!/usr/bin/env python3
"""
Simple test sample creation script
"""

import os
import struct

def create_test_binary():
    """Create a simple test binary for demonstration"""
    
    # Create a simple PE-like header for demonstration
    # This is just for testing purposes - not a real executable
    
    # DOS header
    dos_header = b'MZ'  # DOS signature
    dos_header += b'\x90' * 58  # Padding
    dos_header += struct.pack('<I', 0x80)  # PE header offset
    
    # PE header (simplified)
    pe_header = b'PE\x00\x00'  # PE signature
    pe_header += b'\x00' * 60  # Padding for demo
    
    # Some test strings
    test_strings = [
        b'Hello World',
        b'This is a test string',
        b'https://example.com',
        b'admin@test.com',
        b'192.168.1.1',
        b'kernel32.dll',
        b'CreateFileA',
        b'GetProcAddress',
        b'LoadLibraryA',
        b'VirtualAlloc',
        b'WriteProcessMemory',
        b'ReadProcessMemory'
    ]
    
    # Combine everything
    binary_data = dos_header + pe_header + b'\x00' * 100
    
    # Add test strings at the end
    for string in test_strings:
        binary_data += string + b'\x00'
    
    # Write to file
    with open('test_sample.exe', 'wb') as f:
        f.write(binary_data)
    
    print("Created test_sample.exe for demonstration")
    return 'test_sample.exe'

if __name__ == "__main__":
    create_test_binary()
