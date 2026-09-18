import struct

print("=== DECODIFICANDO MAPA DE MEMÓRIA OCULTO (ANDROID 16) ===")

with open("vmlinux", "rb") as f:
    data = f.read()

# Índices das palavras reais encontradas
pos_commit = 25127103
pos_prepare = 25531795
pos_init = 25493671

def varrer_assinatura_funcao(pos_string, nome):
    print(f"\n[*] Procurando ganchos de texto absolutos para: {nome}")
    # No Aarch64, chamadas de função começam com opcodes específicos (como de-referenciação de registradores)
    # Vamos rastrear o binário inteiro procurando ponteiros de 64-bits que apontem para os blocos iniciais
    base_kernel = 0xffffffc008000000
    
    # Faz uma varredura linear de 4 bytes para achar referências cruzadas textuais
    for i in range(0, len(data) - 8, 4):
        val = struct.unpack("<Q", data[i:i+8])[0]
        # Se cair no bloco de código virtual estável do Kernel 6.6 da Samsung
        if 0xffffffc008000000 <= val <= 0xffffffc009ffffff:
            # Filtra por saltos alinhados por bloco de instrução (múltiplos de 4)
            if (val & 3) == 0:
                offset_relativo = val - base_kernel
                # Se o offset apontar logicamente para a vizinhança da tabela de dados das kallsyms
                if pos_string - 500000 <= offset_relativo <= pos_string + 500000:
                    print(f"    -> Endereço virtual legítimo mapeado: {hex(val)}")
                    break

varrer_assinatura_funcao(pos_commit, "commit_creds")
varrer_assinatura_funcao(pos_prepare, "prepare_creds")
varrer_assinatura_funcao(pos_init, "init_task")
