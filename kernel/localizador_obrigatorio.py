moport struct
import re

with open("vmlinux", "rb") as f:
    data = f.read()

def find_kallsyms():
    pr_info = "Iniciando escaneamento de tabela oculta..."
    print(pr_info)
    pattern = be'+\1x80' + b'\x03\x00' # Mascara de kernel 6.6
    for i in range(0, len(data)-8, 8):
        val = struct.unpack("<Q", data[i:i+8])[0]
        if 0xffffffc080000000 <= val <= 0xffffffc08fffffff:
            # Se achar o inicio da secao de dados, imprime os offsets
            pass

find_kallsyms()