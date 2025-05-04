"""
Encryption Tester module for verifying the encryption functionality.
"""
import os
import subprocess
import hashlib
import tempfile
import time
import logging
import random
import string
import json

logger = logging.getLogger("encryption_tester")

def test_encryption(framework_path, os_type="windows"):
    """
    Test the encryption functionality of the OPSEC Loader framework.
    
    Args:
        framework_path (str): Path to the OPSEC Loader framework
        os_type (str): Operating system type (windows or linux)
        
    Returns:
        dict: Results of the encryption verification
    """
    # Check if the encryption tool exists
    encryption_tool = find_encryption_tool(framework_path)
    if not encryption_tool:
        return {
            "success": False,
            "message": "Encryption tool not found",
            "error": "Missing encrypt_shell.py or similar tool"
        }
    
    # Create test data
    temp_dir = tempfile.mkdtemp()
    test_file = create_test_file(temp_dir)
    output_file = os.path.join(temp_dir, "encrypted.bin")
    key_file = os.path.join(temp_dir, "key.bin")
    
    # Attempt to encrypt the test file
    logger.info(f"Encrypting test file: {test_file}")
    start_time = time.time()
    
    encryption_result = encrypt_file(
        encryption_tool, test_file, output_file, key_file, framework_path
    )
    
    end_time = time.time()
    
    if not encryption_result["success"]:
        return {
            "success": False,
            "message": "Encryption failed",
            "error": encryption_result["error"],
            "command": encryption_result["command"]
        }
    
    # Verify the encrypted file and key
    if not os.path.exists(output_file) or not os.path.exists(key_file):
        return {
            "success": False,
            "message": "Encrypted file or key not created",
            "error": "Output files missing after encryption"
        }
    
    # Test key format and strength
    key_analysis = analyze_key(key_file)
    
    # Test encryption strength
    encryption_analysis = analyze_encryption(test_file, output_file)
    
    # Test key formatter if available
    key_formatter = find_key_formatter(framework_path)
    key_formatting = None
    if key_formatter:
        key_formatting = test_key_formatter(key_formatter, key_file, framework_path)
    
    # Prepare result
    result = {
        "success": True,
        "message": "Encryption functionality verified successfully",
        "encryption_tool": os.path.basename(encryption_tool),
        "original_file": {
            "path": test_file,
            "size": os.path.getsize(test_file),
            "hash": calculate_hash(test_file)
        },
        "encrypted_file": {
            "path": output_file,
            "size": os.path.getsize(output_file),
            "hash": calculate_hash(output_file)
        },
        "key_file": {
            "path": key_file,
            "size": os.path.getsize(key_file),
            "hash": calculate_hash(key_file)
        },
        "encryption_time": round(end_time - start_time, 2),
        "key_analysis": key_analysis,
        "encryption_analysis": encryption_analysis,
        "key_formatting": key_formatting,
        "command_output": encryption_result["output"]
    }
    
    return result

def find_encryption_tool(framework_path):
    """
    Find the encryption tool in the framework.
    
    Args:
        framework_path (str): Path to the OPSEC Loader framework
        
    Returns:
        str or None: Path to the encryption tool if found, None otherwise
    """
    possible_tools = [
        os.path.join(framework_path, "encrypt_shell.py")
    ]
    
    for tool in possible_tools:
        if os.path.exists(tool):
            return tool
    
    return None

def find_key_formatter(framework_path):
    """
    Find the key formatter tool in the framework.
    
    Args:
        framework_path (str): Path to the OPSEC Loader framework
        
    Returns:
        str or None: Path to the key formatter if found, None otherwise
    """
    possible_tools = [
        os.path.join(framework_path, "key_formatter_.py")
    ]
    
    for tool in possible_tools:
        if os.path.exists(tool):
            return tool
    
    return None

def create_test_file(directory, size=1024):
    """
    Create a test file with random data.
    
    Args:
        directory (str): Directory to create the file in
        size (int): Size of the file in bytes
        
    Returns:
        str: Path to the created file
    """
    file_path = os.path.join(directory, "test_data.bin")
    
    with open(file_path, "wb") as f:
        f.write(os.urandom(size))
    
    return file_path

def encrypt_file(encryption_tool, input_file, output_file, key_file, framework_path):
    """
    Encrypt a file using the framework's encryption tool.
    
    Args:
        encryption_tool (str): Path to the encryption tool
        input_file (str): Path to the input file
        output_file (str): Path to save the encrypted file
        key_file (str): Path to save the key file
        framework_path (str): Path to the framework
        
    Returns:
        dict: Result of the encryption attempt
    """
    # Determine the command based on the tool
    tool_name = os.path.basename(encryption_tool)
    
    if tool_name == "encrypt_shell.py":
        command = [
            "python", encryption_tool,
            "--input", input_file,
            "--output", output_file,
            "--key-file", key_file
        ]
    else:
        return {
            "success": False,
            "error": f"Unknown encryption tool: {tool_name}",
            "command": None,
            "output": None
        }
    
    # Run the command
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=framework_path,
            universal_newlines=True
        )
        stdout, stderr = process.communicate(timeout=60)
        
        if process.returncode != 0:
            return {
                "success": False,
                "error": stderr,
                "command": " ".join(command),
                "output": stdout
            }
        
        return {
            "success": True,
            "command": " ".join(command),
            "output": stdout
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "Command timed out",
            "command": " ".join(command),
            "output": None
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "command": " ".join(command),
            "output": None
        }

def calculate_hash(file_path):
    """
    Calculate SHA-256 hash of a file.
    
    Args:
        file_path (str): Path to the file
        
    Returns:
        str: SHA-256 hash of the file
    """
    hash_obj = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_obj.update(chunk)
    return hash_obj.hexdigest()

def analyze_key(key_file):
    """
    Analyze the encryption key for strength and format.
    
    Args:
        key_file (str): Path to the key file
        
    Returns:
        dict: Analysis results
    """
    try:
        with open(key_file, "rb") as f:
            key_data = f.read()
        
        key_size = len(key_data) * 8  # Size in bits
        
        # Check if key size matches AES-256 (32 bytes)
        is_aes_256 = len(key_data) == 32
        
        # Check entropy (randomness) of the key
        entropy = calculate_entropy(key_data)
        
        # Detect if there's an IV in the key file (common AES-CBC format: 32 bytes key + 16 bytes IV)
        has_iv = len(key_data) == 48
        
        return {
            "key_size_bits": key_size,
            "is_aes_256": is_aes_256,
            "entropy": round(entropy, 2),
            "entropy_quality": "High" if entropy > 7.5 else "Medium" if entropy > 6.5 else "Low",
            "has_iv": has_iv,
            "total_size_bytes": len(key_data)
        }
    except Exception as e:
        return {
            "error": str(e),
            "key_size_bits": None,
            "is_aes_256": False
        }

def analyze_encryption(original_file, encrypted_file):
    """
    Analyze the encryption quality.
    
    Args:
        original_file (str): Path to the original file
        encrypted_file (str): Path to the encrypted file
        
    Returns:
        dict: Analysis results
    """
    try:
        with open(original_file, "rb") as f:
            original_data = f.read()
        
        with open(encrypted_file, "rb") as f:
            encrypted_data = f.read()
        
        # Check size difference
        original_size = len(original_data)
        encrypted_size = len(encrypted_data)
        size_change_percent = ((encrypted_size - original_size) / original_size) * 100 if original_size > 0 else 0
        
        # Calculate byte-level differences
        min_length = min(len(original_data), len(encrypted_data))
        differences = sum(1 for i in range(min_length) if original_data[i] != encrypted_data[i])
        difference_percent = (differences / min_length) * 100 if min_length > 0 else 0
        
        # Check for patterns
        has_patterns = detect_patterns(encrypted_data)
        
        # Check for empty blocks or repeating sequences
        has_empty_blocks = has_zero_blocks(encrypted_data)
        
        # Calculate entropy of encrypted data
        entropy = calculate_entropy(encrypted_data)
        
        return {
            "size_change_percent": round(size_change_percent, 2),
            "byte_difference_percent": round(difference_percent, 2),
            "has_patterns": has_patterns,
            "has_empty_blocks": has_empty_blocks,
            "encrypted_entropy": round(entropy, 2),
            "encryption_strength": "Strong" if entropy > 7.8 and difference_percent > 90 else "Medium" if entropy > 7.0 else "Weak"
        }
    except Exception as e:
        return {
            "error": str(e),
            "encryption_strength": "Unknown"
        }

def test_key_formatter(key_formatter, key_file, framework_path):
    """
    Test the key formatter tool.
    
    Args:
        key_formatter (str): Path to the key formatter
        key_file (str): Path to the key file
        framework_path (str): Path to the framework
        
    Returns:
        dict: Results of the key formatter test
    """
    temp_dir = tempfile.mkdtemp()
    output_file = os.path.join(temp_dir, "formatted_key.h")
    
    command = [
        "python", key_formatter,
        "--input", key_file,
        "--output", output_file
    ]
    
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=framework_path,
            universal_newlines=True
        )
        stdout, stderr = process.communicate(timeout=60)
        
        success = process.returncode == 0 and os.path.exists(output_file)
        
        if success:
            with open(output_file, "r") as f:
                formatter_output = f.read()
            
            # Check if output is a C/C++ header file
            is_c_header = "unsigned char" in formatter_output or "BYTE" in formatter_output
            
            return {
                "success": True,
                "is_c_header": is_c_header,
                "output_file": output_file,
                "output_size": os.path.getsize(output_file)
            }
        else:
            return {
                "success": False,
                "error": stderr
            }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

def calculate_entropy(data):
    """
    Calculate Shannon entropy of data.
    
    Args:
        data (bytes): Data to calculate entropy for
        
    Returns:
        float: Entropy value (0-8, with 8 being maximum randomness for bytes)
    """
    if not data:
        return 0
    
    # Count byte occurrences
    byte_counts = {}
    for byte in data:
        if byte not in byte_counts:
            byte_counts[byte] = 0
        byte_counts[byte] += 1
    
    # Calculate entropy
    entropy = 0
    for count in byte_counts.values():
        probability = count / len(data)
        entropy -= probability * (math.log(probability) / math.log(2))
    
    return entropy

def detect_patterns(data, block_size=16):
    """
    Detect if there are repeating patterns in the data.
    
    Args:
        data (bytes): Data to analyze
        block_size (int): Size of blocks to check
        
    Returns:
        bool: True if patterns detected, False otherwise
    """
    if len(data) < block_size * 2:
        return False
    
    blocks = {}
    for i in range(0, len(data) - block_size, block_size):
        block = data[i:i+block_size]
        if block in blocks:
            blocks[block] += 1
        else:
            blocks[block] = 1
    
    # If any block repeats more than what would be expected in random data
    max_repeats = max(blocks.values()) if blocks else 0
    return max_repeats > 2  # More than 2 identical blocks suggests patterns

def has_zero_blocks(data, block_size=16):
    """
    Check if the data contains blocks of zeros.
    
    Args:
        data (bytes): Data to analyze
        block_size (int): Size of blocks to check
        
    Returns:
        bool: True if zero blocks found, False otherwise
    """
    zero_block = bytes([0] * block_size)
    
    for i in range(0, len(data) - block_size, block_size):
        if data[i:i+block_size] == zero_block:
            return True
    
    return False

# Add math module import for entropy calculation
import math
