"""
PE Analyzer module for testing the PE to Shellcode conversion functionality.
"""
import os
import subprocess
import hashlib
import tempfile
import time
import random
import logging

logger = logging.getLogger("pe_analyzer")

def analyze_pe(framework_path, pe_file_path=None, os_type="windows"):
    """
    Analyze the PE to Shellcode conversion functionality.
    
    Args:
        framework_path (str): Path to the OPSEC Loader framework
        pe_file_path (str, optional): Path to a PE file for testing
        os_type (str): Operating system type (windows or linux)
        
    Returns:
        dict: Results of the PE to Shellcode conversion verification
    """
    # Check if the required conversion tools exist
    pe2sc_path = find_converter_tool(framework_path)
    if not pe2sc_path:
        return {
            "success": False,
            "message": "PE to Shellcode converter tool not found",
            "error": "Missing custom_pe2sc.py or havoc_to_shellcode.py"
        }
    
    # If no PE file is provided, look for a sample or create one
    if not pe_file_path:
        pe_file_path = find_sample_pe(framework_path, os_type)
        if not pe_file_path:
            return {
                "success": False,
                "message": "No PE file provided and no sample found",
                "error": "Missing test executable"
            }
    
    # Create temporary directory for output
    temp_dir = tempfile.mkdtemp()
    output_file = os.path.join(temp_dir, "output.bin")
    
    # Attempt to convert PE to Shellcode
    logger.info(f"Converting PE file: {pe_file_path}")
    start_time = time.time()
    
    conversion_result = convert_pe_to_shellcode(
        pe2sc_path, pe_file_path, output_file, framework_path
    )
    
    end_time = time.time()
    
    if not conversion_result["success"]:
        return {
            "success": False,
            "message": "PE to Shellcode conversion failed",
            "error": conversion_result["error"],
            "command": conversion_result["command"]
        }
    
    # Verify the output shellcode
    if not os.path.exists(output_file):
        return {
            "success": False,
            "message": "Shellcode file not created",
            "error": "Output file missing after conversion"
        }
    
    # Get file info
    pe_size = os.path.getsize(pe_file_path)
    shellcode_size = os.path.getsize(output_file)
    
    # Calculate hashes
    pe_hash = calculate_hash(pe_file_path)
    shellcode_hash = calculate_hash(output_file)
    
    # Test multiple generations to verify polymorphism
    polymorphic_test = test_polymorphism(pe2sc_path, pe_file_path, framework_path)
    
    # Prepare result
    result = {
        "success": True,
        "message": "PE to Shellcode conversion verified successfully",
        "conversion_tool": os.path.basename(pe2sc_path),
        "original_pe": {
            "path": pe_file_path,
            "size": pe_size,
            "hash": pe_hash
        },
        "shellcode": {
            "path": output_file,
            "size": shellcode_size,
            "hash": shellcode_hash
        },
        "conversion_time": round(end_time - start_time, 2),
        "size_ratio": round(shellcode_size / pe_size, 2) if pe_size > 0 else None,
        "polymorphic_test": polymorphic_test,
        "command_output": conversion_result["output"]
    }
    
    return result

def find_converter_tool(framework_path):
    """
    Find the PE to Shellcode converter tool in the framework.
    
    Args:
        framework_path (str): Path to the OPSEC Loader framework
        
    Returns:
        str or None: Path to the converter tool if found, None otherwise
    """
    possible_tools = [
        os.path.join(framework_path, "custom_pe2sc.py"),
        os.path.join(framework_path, "havoc_to_shellcode.py")
    ]
    
    for tool in possible_tools:
        if os.path.exists(tool):
            return tool
    
    return None

def find_sample_pe(framework_path, os_type):
    """
    Find a sample PE file for testing.
    
    Args:
        framework_path (str): Path to the OPSEC Loader framework
        os_type (str): Operating system type (windows or linux)
        
    Returns:
        str or None: Path to a sample PE file if found, None otherwise
    """
    # Common locations for sample files
    possible_locations = [
        os.path.join(framework_path, "samples"),
        os.path.join(framework_path, "test"),
        os.path.join(framework_path, "examples")
    ]
    
    extensions = [".exe", ".dll"] if os_type.lower() == "windows" else [".elf", ".so"]
    
    for location in possible_locations:
        if os.path.exists(location) and os.path.isdir(location):
            for root, _, files in os.walk(location):
                for file in files:
                    if any(file.lower().endswith(ext) for ext in extensions):
                        return os.path.join(root, file)
    
    # If no sample found, use a system file if on Windows
    if os.type.lower() == "windows" and os.path.exists("C:\\Windows\\System32\\calc.exe"):
        return "C:\\Windows\\System32\\calc.exe"
    
    return None

def convert_pe_to_shellcode(converter_path, pe_file, output_file, framework_path):
    """
    Convert a PE file to shellcode using the framework's converter.
    
    Args:
        converter_path (str): Path to the converter tool
        pe_file (str): Path to the PE file
        output_file (str): Path to save the output shellcode
        framework_path (str): Path to the framework
        
    Returns:
        dict: Result of the conversion attempt
    """
    # Determine the command based on the converter
    tool_name = os.path.basename(converter_path)
    
    if tool_name == "custom_pe2sc.py":
        command = [
            "python", converter_path,
            "--input", pe_file,
            "--output", output_file,
            "--polymorphic"
        ]
    elif tool_name == "havoc_to_shellcode.py":
        command = [
            "python", converter_path,
            "-f", pe_file,
            "-o", output_file
        ]
    else:
        return {
            "success": False,
            "error": f"Unknown converter tool: {tool_name}",
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

def test_polymorphism(converter_path, pe_file, framework_path, iterations=3):
    """
    Test if the shellcode generated is polymorphic by generating multiple samples.
    
    Args:
        converter_path (str): Path to the converter tool
        pe_file (str): Path to the PE file
        framework_path (str): Path to the framework
        iterations (int): Number of iterations to test
        
    Returns:
        dict: Results of the polymorphism test
    """
    temp_dir = tempfile.mkdtemp()
    hashes = []
    sizes = []
    
    for i in range(iterations):
        output_file = os.path.join(temp_dir, f"output_{i}.bin")
        
        result = convert_pe_to_shellcode(
            converter_path, pe_file, output_file, framework_path
        )
        
        if not result["success"] or not os.path.exists(output_file):
            return {
                "is_polymorphic": False,
                "error": "Failed to generate sample",
                "unique_hashes": 0,
                "size_variation": 0
            }
        
        file_hash = calculate_hash(output_file)
        file_size = os.path.getsize(output_file)
        
        hashes.append(file_hash)
        sizes.append(file_size)
    
    # Calculate polymorphism metrics
    unique_hashes = len(set(hashes))
    is_polymorphic = unique_hashes > 1
    
    # Calculate size variation as standard deviation percentage
    if len(sizes) > 1:
        avg_size = sum(sizes) / len(sizes)
        variance = sum((size - avg_size) ** 2 for size in sizes) / len(sizes)
        std_dev = variance ** 0.5
        size_variation = (std_dev / avg_size) * 100 if avg_size > 0 else 0
    else:
        size_variation = 0
    
    return {
        "is_polymorphic": is_polymorphic,
        "unique_hashes": unique_hashes,
        "total_samples": iterations,
        "size_variation": round(size_variation, 2),
        "polymorphic_variations": {
            "labels": [f"Sample {i+1}" for i in range(iterations)],
            "sizes": sizes,
            "hashes": hashes
        }
    }
