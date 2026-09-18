import struct

print("Iniciando varredura local e cirúrgica do vmlinux...")

try:
    with open("vmlinux", "rb") as f:
        data = f.read()
except FileNotFoundError:
    print("[-] Erro: O arquivo 'vmlinux' nao foi encontrado nesta pasta. Certifique-se de estar no diretorio correto.")
    exit(1)

alvos = [b"commit_creds\x00", b"prepare_creds\x00", b"init_task\x00"]

for alvo in alvos:
    idx = data.find(alvo)
    if idx != -1:
        print(f"\n[+] Nome encontrado: {alvo.decode().replace('\x00', '')}")
        
        # Varre o binario em busca de ponteiros de 64-bits (8 bytes) alinhados
        # Procurando a tabela de kallsyms ou vetores de simbolos
        for i in range(0, len(data) - 8, 8):
            bloco = data[i:i+8]
            val = struct.unpack("<Q", bloco)[0]
            # Filtra apenas os enderecos que caem no espaco virtual do Kernel Linux de 64-bits
            if 0xffffffc000000000 <= val <= 0xffffffcfffffffff:
                # Se o ponteiro aponta para a vizinhanca do nome do simbolo
                if idx - 16384 <= (val & 0xffffffff) <= idx + 16384:
                    print(f"    -> Endereco mapeado: {hex(val)}")
                    break
