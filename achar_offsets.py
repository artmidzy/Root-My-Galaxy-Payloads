import struct

print("Iniciando varredura local e cirúrgica do vmlinux...")

with open("vmlinux", "rb") as f:
    data = f.read()

# Alvos em texto puro que o strings localizou
alvos = [b"commit_creds\x00", b"prepare_creds\x00", b"init_task\x00"]

for alvo in alvos:
    idx = data.find(alvo)
    if idx != -1:
        # Procurar ponteiros de 64-bits (8 bytes) que apontam para essa região de texto
        # No Aarch64, os endereços do Kernel começam com 0xffffffc0...
        print(f"\n[+] Nome encontrado: {alvo.decode().strip()}")
        
        # Escaneia a vizinhança do offset em busca da tabela de ponteiros relativa
        for i in range(max(0, idx - 4096), min(len(data), idx + 4096), 8):
            bloco = data[i:i+8]
            if len(bloco) == 8:
                val = struct.unpack("<Q", bloco)[0]
                # Verifica se o valor bate com a máscara de memória do Kernel do A34
                if 0xffffffc000000000 <= val <=最高 0xffffffc08fffffff:
                    print(f"    -> Possível ponteiro associado: {hex(val)}")
