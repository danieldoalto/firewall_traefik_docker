# Firewall Management Script

Este projeto contém um script Python para gerenciar regras de firewall `iptables` de forma flexível, segura e automatizada, usando uma `chain` dedicada para whitelisting.

## Funcionalidades

- **Gerenciamento de Portas**: Bloqueia (`DROP`) ou libera (`ACCEPT`) o acesso a um conjunto de portas definidas em `config.yml`.
- **Whitelist de IPs com Chain Dedicada**: Garante que uma lista de IPs sempre tenha acesso prioritário. O script cria e gerencia uma `chain` `whitelist` no `iptables` para garantir que essas regras sejam processadas primeiro.
- **Portas Essenciais Configuráveis**: Uma lista `never_block_ports` em `config.yml` permite definir portas críticas (como SSH) que o script nunca deve bloquear.
- **Gerenciamento Preciso de Regras**: O script rastreia as regras que aplica em `.fw-last-rules.log`, permitindo uma remoção exata sem afetar regras preexistentes.
- **Backup e Restore**: Salva e restaura o estado completo das regras do `iptables`.
- **Logging**: Todas as operações são registradas em `fw.log` para auditoria.

## Arquivos

- `fw.py`: O script principal.
- `config.yml`: Arquivo de configuração para definir portas, whitelists, etc.
- `requirements.txt`: Dependências Python do projeto.
- `fw.log`: Arquivo de log gerado automaticamente.
- `.fw-last-rules.log`: Arquivo temporário com as últimas regras aplicadas (usado pela opção `-f`).
- `iptables.backup`: Arquivo de backup gerado com a opção `-b`.

## Como Usar

### 1. Instalação

Instale a dependência `PyYAML`:

```bash
pip install -r requirements.txt
```

### 2. Configuração

Edite o arquivo `config.yml`:

- `whitelist_ips`: Adicione IPs ou ranges (formato CIDR) que sempre terão acesso.
- `never_block_ports`: Liste as portas essenciais que nunca devem ser bloqueadas.
- `managed_ports`: Liste as portas que você quer controlar (bloquear ou liberar).

Exemplo de `config.yml`:
```yaml
whitelist_ips:
  - 192.168.1.100
  - 10.0.0.0/24

never_block_ports:
  - 22
  - 80
  - 443

managed_ports:
  - 3000
  - 5000
  - 9000
```

### 3. Execução

**Importante**: O script precisa de privilégios de root. Use `sudo`.

- **Bloquear as portas gerenciadas:** (Comando padrão)
  ```bash
  sudo python3 fw.py
  ```

- **Liberar as portas gerenciadas:**
  ```bash
  sudo python3 fw.py -l
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
