import sys
import dis
import base64
import zlib
from datetime import datetime
import binascii
import marshal
import types

# Encoded constants
_0x = lambda x: base64.b64decode(x).decode()
_1x = lambda x: zlib.decompress(base64.b64decode(x))
_2x = lambda x: marshal.loads(base64.b64decode(x))

# Encoded strings
_USER = _0x('R2VvcmdlLUNvZHI=')  # Encoded "George-Codr"
_TIME = _0x('MjAyNS0wMS0yMiAwNzowMDo0MQ==')  # Encoded timestamp
_INFO = _2x(b'4wAAAAAAAAAAAAAAAAs=')  # Encoded code object

class CodeManager:
    def __init__(self, key):
        self.key = key ^ 0xFF
        
    def __call__(self, x):
        return bytes(b ^ self.key for b in x)

def create_dynamic_code(code_bytes, globals_dict):
    try:
        return types.FunctionType(
            marshal.loads(code_bytes),
            globals_dict
        )
    except:
        return lambda: None

# Anti-debug mechanism
def verify_environment():
    try:
        if sys.gettrace() is not None:
            return False
        return True
    except:
        return False

# Obfuscated version check
def _check_version():
    return [
        x ^ y for x, y in zip(
            map(ord, str(sys.version_info[0])),
            [0x7F, 0x7E, 0x7D]
        )
    ]

# Dynamic code generation
def generate_code(seed):
    code_fragments = [
        lambda x: x + 1,
        lambda x: x * 2,
        lambda x: x ^ 0xFF
    ]
    return lambda x: code_fragments[seed % len(code_fragments)](x)

class VersionWrapper:
    def __init__(self):
        self._version = None
        self._check = verify_environment()
    
    @property
    def info(self):
        if not self._check:
            raise RuntimeError("Invalid environment")
        if not self._version:
            self._version = sys.version
        return self._version

def _execute_operation(op, value):
    operators = {
        0: lambda x: x + 1,
        1: lambda x: x - 1,
        2: lambda x: x ^ 0xFF,
        3: lambda x: x << 1,
        4: lambda x: x >> 1
    }
    return operators.get(op % len(operators), lambda x: x)(value)

class SystemInfoProvider:
    def __init__(self):
        self._user = _USER
        self._time = _TIME
        self._version_wrapper = VersionWrapper()
        self._ops = []
        
    def _transform_data(self, data):
        result = []
        for i, char in enumerate(data):
            result.append(_execute_operation(i, ord(char)))
        return bytes(result)
    
    def get_info(self):
        if not verify_environment():
            raise RuntimeError("Invalid execution environment")
            
        info = {
            'user': self._user,
            'time': self._time,
            'python_version': self._version_wrapper.info
        }
        
        # Add dynamic checks
        info['checksums'] = [
            binascii.crc32(str(x).encode()) 
            for x in [info['user'], info['time']]
        ]
        
        return info

def main():
    try:
        # Initialize provider
        provider = SystemInfoProvider()
        info = provider.get_info()
        
        # Version verification
        version_check = _check_version()
        if not all(x > 0 for x in version_check):
            raise RuntimeError("Unsupported Python version")
        
        # Dynamic code execution
        code_gen = generate_code(sum(version_check))
        
        # Process and display information
        print(f"System Information:")
        print("-" * 50)
        print(f"User: {info['user']}")
        print(f"Time (UTC): {info['time']}")
        print(f"Python Version: {info['python_version']}")
        
        # Additional security checks
        checksums = info['checksums']
        if not all(isinstance(x, int) for x in checksums):
            raise ValueError("Invalid checksum values")
        
        # Generate dynamic verification code
        verify_code = code_gen(checksums[0] & 0xFF)
        if verify_code <= 0:
            raise ValueError("Verification failed")
            
    except Exception as e:
        print(f"Error: {str(e)}")
        return False
        
    return True

if __name__ == "__main__" and verify_environment():
    main()
