"""
Verification module for the OPSEC Loader framework.
This module coordinates the verification of all framework components.
"""
import os
import subprocess
import logging
import json
import time
from .pe_analyzer import analyze_pe
from .encryption_tester import test_encryption
from .memory_execution import test_memory_execution
from .evasion_checker import check_evasion
from .cleanup_validator import validate_cleanup

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("verification")

def verify_workflow(framework_path, os_type="windows", pe_file_path=None):
    """
    Verify the complete OPSEC Loader framework workflow.
    
    Args:
        framework_path (str): Path to the OPSEC Loader framework
        os_type (str): Operating system type (windows or linux)
        pe_file_path (str, optional): Path to a PE file for testing
        
    Returns:
        dict: Results of the verification for each component
    """
    logger.info(f"Starting verification of OPSEC Loader framework at: {framework_path}")
    logger.info(f"Operating system: {os_type}")
    
    results = {}
    
    # Verify that the framework path exists
    if not os.path.exists(framework_path):
        logger.error(f"Framework path does not exist: {framework_path}")
        raise FileNotFoundError(f"Framework path does not exist: {framework_path}")
    
    # Identify framework components
    components = identify_components(framework_path)
    logger.info(f"Identified components: {components}")
    
    # 1. Verify PE to Shellcode conversion
    logger.info("Verifying PE to Shellcode conversion...")
    try:
        results["pe_conversion"] = analyze_pe(framework_path, pe_file_path, os_type)
        logger.info("PE to Shellcode conversion verification completed")
    except Exception as e:
        logger.error(f"PE to Shellcode conversion verification failed: {str(e)}")
        results["pe_conversion"] = {
            "success": False,
            "message": f"Verification failed: {str(e)}",
            "error": str(e)
        }
    
    # 2. Verify encryption
    logger.info("Verifying encryption...")
    try:
        results["encryption"] = test_encryption(framework_path, os_type)
        logger.info("Encryption verification completed")
    except Exception as e:
        logger.error(f"Encryption verification failed: {str(e)}")
        results["encryption"] = {
            "success": False,
            "message": f"Verification failed: {str(e)}",
            "error": str(e)
        }
    
    # 3. Verify memory execution
    logger.info("Verifying memory execution...")
    try:
        results["memory_execution"] = test_memory_execution(framework_path, os_type)
        logger.info("Memory execution verification completed")
    except Exception as e:
        logger.error(f"Memory execution verification failed: {str(e)}")
        results["memory_execution"] = {
            "success": False,
            "message": f"Verification failed: {str(e)}",
            "error": str(e)
        }
    
    # 4. Verify EDR/AV evasion
    logger.info("Verifying EDR/AV evasion...")
    try:
        results["evasion"] = check_evasion(framework_path, os_type)
        logger.info("EDR/AV evasion verification completed")
    except Exception as e:
        logger.error(f"EDR/AV evasion verification failed: {str(e)}")
        results["evasion"] = {
            "success": False,
            "message": f"Verification failed: {str(e)}",
            "error": str(e)
        }
    
    # 5. Verify cleanup
    logger.info("Verifying cleanup...")
    try:
        results["cleanup"] = validate_cleanup(framework_path, os_type)
        logger.info("Cleanup verification completed")
    except Exception as e:
        logger.error(f"Cleanup verification failed: {str(e)}")
        results["cleanup"] = {
            "success": False,
            "message": f"Verification failed: {str(e)}",
            "error": str(e)
        }
    
    # Determine overall success
    all_success = all(component.get("success", False) for component in results.values())
    
    # Add overall status
    results["overall"] = {
        "success": all_success,
        "message": "All components verified successfully" if all_success else "Some components failed verification",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    
    logger.info(f"Verification completed with overall status: {'Success' if all_success else 'Failed'}")
    return results

def identify_components(framework_path):
    """
    Identify the components present in the OPSEC Loader framework.
    
    Args:
        framework_path (str): Path to the OPSEC Loader framework
        
    Returns:
        dict: Information about the identified components
    """
    components = {
        "pe_conversion": False,
        "encryption": False,
        "memory_execution": False,
        "cleanup": False
    }
    
    # Look for specific files to identify components
    component_files = {
        "pe_conversion": ["custom_pe2sc.py", "havoc_to_shellcode.py"],
        "encryption": ["encrypt_shell.py", "key_formatter_.py"],
        "memory_execution": ["opsec_loader.cpp"],
        "cleanup": ["clean_traces.sh", "opsec_run.ps1", "opsec_run.sh"]
    }
    
    for component, files in component_files.items():
        for file in files:
            file_path = os.path.join(framework_path, file)
            if os.path.exists(file_path):
                components[component] = True
                break
    
    return components

def run_command(command, cwd=None, timeout=60):
    """
    Run a command and return its output.
    
    Args:
        command (list): Command to run as a list of arguments
        cwd (str, optional): Current working directory
        timeout (int, optional): Timeout in seconds
        
    Returns:
        tuple: (stdout, stderr, return_code)
    """
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            universal_newlines=True
        )
        stdout, stderr = process.communicate(timeout=timeout)
        return stdout, stderr, process.returncode
    except subprocess.TimeoutExpired:
        process.kill()
        return "", "Command timed out", 1
    except Exception as e:
        return "", str(e), 1
