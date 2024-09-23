# ShellcodeRunnerAspx_Generator.py

**ShellcodeRunnerAspx_Generator.py** is a Python tool that takes a `.bin` shellcode file, encrypts it using the RC4 algorithm, and generates a `.aspx` file that can be executed on a web server to inject and run the shellcode remotely using Windows API calls.

## 🔑 Key Features:
- 🔐 **RC4 Encryption**: Encrypts the shellcode using the RC4 encryption algorithm for additional obfuscation.
- 🛠 **Dynamic ASPX File Generation**: Generates a custom `.aspx` file that decrypts and injects the shellcode into a target process.
- 🚀 **Optimized ASPX Template**: The `.aspx` template decrypts the shellcode and executes it in memory using Windows API functions like `VirtualAlloc` and `CreateThread`.
- 🌐 **Shellcode Execution on IIS Servers**: The generated `.aspx` file can be used to execute shellcode on IIS web servers.

## 📝 Usage

### Running the Script:
```bash
python3 ShellcodeRunnerAspx_Generator.py <shellcode.bin> <output_file.aspx>
```
### Example 

```bash
python3 ShellcodeRunnerAspx_Generator.py shellcode.bin reverse_shell.aspx
```
