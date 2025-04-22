import readline, code
import unicodedata
import re

def readfilter(*args, **kwargs):
    inline = input(*args, **kwargs)
    
    normalized_input = unicodedata.normalize('NFKC', inline)
    
    normalized_input_lower = normalized_input.lower()
    
    for term in blist:
        if term.lower() in normalized_input_lower:
            print(f"Interdit: contient un terme blacklisté '{term}'")
            return ""
    
    if re.search(r'\\x[0-9a-fA-F]{2}|\\[0-7]{1,3}|\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8}', normalized_input):
        print("Echappe toi de la prison, pas les charactères: contient du code escape")
        return ""
    
    normalized_no_space = re.sub(r'\s+', '', normalized_input_lower)
    for term in blist:
        if term.lower() in normalized_no_space:
            print(f"GG here is your flag: .... SIKEEEEEEE: contient code obfusqué'{term}'")
            return ""
    
    if re.search(r'__[a-zA-Z]+__', normalized_input):
        print("T'as cru que j'étais une dinde (dunder): contient un dunder")
        return ""
    
    if re.search(r'chr\s*\(\s*\d+\s*\)|ord\s*\(', normalized_input_lower):
        print("Bien essayé: contient manipulation de code")
        return ""
    
    return inline

blist = [
    'import', 'eval', 'exec', 'compile', 'system', 'builtins', 'loader', 
    'dict', 'os', 'listdir', 'getattr', 'module', 'class', 'loader', 
    'getattribute', 'locals', 'base', 'subclasses', 'read', 'load_module', 
    'popen', 'open', 'globals', 'subprocess', 'nc', 'bash', 'code', '+', 
    'object', 'find_spec', '[', ']', '__import__', '__builtins__', 
    'breakpoint', 'pty', 'spawn', 'pickle', 'marshal', 'shelve',
    'execfile', 'reload', 'input', 'help', 'credits',
    'exit', 'quit', 'dir', 'vars', 'type', 'id', 'repr', 'chr', 'ord',
    'memoryview', 'lambda', '`', 'inspect', 'frame', 'sys', 'platform',
    'bytearray', 'fromhex', 'encode', 'decode', 'dumps', 'loads', 'yaml',
    'json', 'xml', 'socket', 'connect', 'bind', 'listen', 'accept',
    'contextlib', 'pty', 'dup', 'fcntl', 'struct', 'shutil', 'tempfile',
    'request', 'urllib', 'http', 'ftp', 'telnet', 'ssh', 'ctypes',
    'cdll', 'windll', 'resource', 'setrlimit', 'getpass', 'crypt',
    'signal', 'posix', 'spawn', 'fork', 'daemon', 'argv', 'environ'
]

print("Mathias vient de te punir pour tes retards, échappe toi de la prison ou aurore va t'attraper...\n")
print(f"Blacklist: {blist}")
code.interact(banner=f"Secure Python Jail - Blacklist: {blist}", readfunc=readfilter)
