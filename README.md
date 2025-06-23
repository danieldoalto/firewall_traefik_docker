# Firewall Management Script

Este projeto contém um script Python para gerenciar regras de firewall `iptables` de forma flexível, segura e automatizada.

## Funcionalidades

- **Bloquear/Liberar Portas**: Bloqueia ou libera o acesso a um conjunto de portas definidas em `config.yml`.
- **Whitelist de IPs**: Garante que uma lista de IPs ou ranges de IPs sempre tenha acesso, independentemente das outras regras.
- **Gerenciamento Preciso**: O script agora rastreia as regras que aplica, permitindo uma remoção exata sem afetar regras preexistentes.
- **Backup e Restore**: Salva e restaura o estado completo das regras do `iptables`.
- **Logging**: Todas as operações são registradas em `fw.log` para auditoria.

## Arquivos

- `fw.py`: O script principal.
- `config.yml`: Arquivo de configuração para definir portas, whitelist, etc.
- `requirements.txt`: Dependências Python do projeto.
- `fw.log`: Arquivo de log gerado automaticamente.
- `.fw-last-rules.log`: Arquivo temporário com as últimas regras aplicadas (usado pela opção `-f`).
- `iptables.backup`: Arquivo de backup gerado com a opção `-b`.

## Como Usar

### 1. Instalação

O script usa a biblioteca `PyYAML` para ler o arquivo de configuração. Se você já executou o `pip install -r requirements.txt` anteriormente, não precisa fazer de novo.

```bash
pip install -r requirements.txt
```

### 2. Configuração

Edite o arquivo `config.yml` para definir suas preferências:

- `whitelist_ips`: Adicione IPs ou ranges de IPs (formato CIDR) que sempre devem ter acesso.
- `managed_ports`: Liste as portas que você quer controlar (bloquear ou liberar).

Exemplo de `config.yml`:
```yaml
whitelist_ips:
  - 192.168.1.100
  - 10.0.0.0/24

managed_ports:
  - 3000
  - 5000
  - 9000
```

### 3. Execução

**Importante**: O script precisa de privilégios de root para gerenciar o `iptables`. Use `sudo`.

- **Bloquear as portas gerenciadas:** (Comando padrão)
  ```bash
  sudo python3 fw.py
  ```

- **Liberar as portas gerenciadas para acesso externo:**
  ```bash
  sudo python3 fw.py -n
  ```

- **Remover as regras da última execução:**
  ```bash
  sudo python3 fw.py -f
  ```

- **Fazer um backup de todas as regras atuais:**
  ```bash
  sudo python3 fw.py -b
  ```

- **Restaurar as regras a partir do backup:**
  ```bash
  sudo python3 fw.py -r
  ```
