import struct

print("=== EXTRAÇÃO CIRÚRGICA DE OFFSETS DO GALAXY A34 ===")

with open("vmlinux", "rb") as f:
    data = f.read()

# Índices físicos que o seu grep localizou no vmlinux
pos_commit = [25127103, 25444394, 25477711, 25625638, 25638198, 29890457, 31756170]
pos_prepare = [25531795, 29890310, 30691062]
pos_init = [25493671, 29970788, 30172868, 30738773]

def escanear_tabela(posicoes, nome):
    print(f"\n[*] Analisando ponteiros para: {nome}")
    encontrados = set()
    
    # Varre a tabela de ponteiros relativa (kallsyms_offsets)
    # Procurando referências de 64-bits que apontam para o espaço virtual do Kernel
    for pos in posicoes:
        # Escaneia um bloco de 64KB ao redor de onde a string está salva
        # para mapear a tabela de endereços virtuais
        for i in range(max(0, pos - 65536), min(len(data), pos + 65536), 8):
            bloco = data[i:i+8]
            if len(bloco) == 8:
                val = struct.unpack("<Q", bloco)[0]
                # Filtra pela máscara padrão do Kernel Aarch64 da Samsung (ffffffc0...)
                if 0xffffffc000000000 <= val <= 0xffffffcfffffffff:
                    # Garante que não é um ponteiro nulo ou repetido na amostragem
                    if val not in encontrados and (val & 0xffffffff) != 0:
                        encontrados.add(val)
                        print(f"    -> {nome} encontrado: {hex(val)}")

escanear_tabela(pos_commit, "commit_creds")
escanear_tabela(pos_prepare, "prepare_creds")
escanear_tabela(pos_init, "init_task")

