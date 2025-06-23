import subprocess
import sys
import logging
import yaml
import os

# --- Configuração ---
CONFIG_FILE = 'config.yml'
LOG_FILE = 'fw.log'
BACKUP_FILE = 'iptables.backup'
LAST_RULES_FILE = '.fw-last-rules.log'
RULE_COMMENT = 'managed-by-fw-script'
WHITELIST_CHAIN = 'whitelist'

# --- Configuração do Logging ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

def run_command(command, stdin_file=None):
    """Executa um comando no shell e lida com erros."""
    # A junção é apenas para o log, o comando é executado como uma lista
    logging.info(f"Executando: {' '.join(command)}")
    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            stdin=stdin_file
        )
        if result.stdout:
            logging.info(f"Saída: {result.stdout.strip()}")
        return result
    except subprocess.CalledProcessError as e:
        logging.error(f"Erro ao executar: {' '.join(command)}")
        logging.error(f"Stderr: {e.stderr.strip()}")
        if 'Permission denied' in e.stderr:
            logging.error("Dica: Execute o script com 'sudo'.")
        sys.exit(1)
    except FileNotFoundError:
        logging.error(f"Erro: 'iptables' não encontrado. Verifique se está instalado.")
        sys.exit(1)

def record_rule(command):
    """Grava um comando de regra no arquivo de log para remoção posterior."""
    with open(LAST_RULES_FILE, 'a') as f:
        f.write(' '.join(command) + '\n')

def clear_last_rules_file():
    """Limpa o arquivo de log de regras da execução anterior."""
    if os.path.exists(LAST_RULES_FILE):
        os.remove(LAST_RULES_FILE)

def load_config():
    """Carrega a configuração do arquivo config.yml."""
    try:
        with open(CONFIG_FILE, 'r') as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        logging.error(f"Arquivo de configuração '{CONFIG_FILE}' não encontrado.")
        return {}
    except yaml.YAMLError as e:
        logging.error(f"Erro ao ler o arquivo YAML '{CONFIG_FILE}': {e}")
        return {}

def get_existing_rules(chain):
    """Retorna uma lista de regras existentes para uma dada chain."""
    try:
        result = subprocess.run(['sudo', 'iptables', '-S', chain], check=True, capture_output=True, text=True)
        return result.stdout.strip().split('\n')
    except subprocess.CalledProcessError:
        return []

def setup_base_firewall():
    """Garante que a estrutura base do firewall (chain de whitelist e saltos) está configurada."""
    logging.info("--- Verificando e configurando a estrutura base do firewall ---")
    
    # 1. Criar a chain 'whitelist' se não existir
    try:
        subprocess.run(['sudo', 'iptables', '-L', WHITELIST_CHAIN], check=True, capture_output=True)
    except subprocess.CalledProcessError:
        logging.info(f"Chain '{WHITELIST_CHAIN}' não encontrada. Criando...")
        run_command(['sudo', 'iptables', '-N', WHITELIST_CHAIN])

    # 2. Garantir que o salto para a whitelist está no topo de INPUT e FORWARD
    for chain in ['INPUT', 'FORWARD']:
        rules = get_existing_rules(chain)
        jump_rule = f'-A {chain} -j {WHITELIST_CHAIN}' # O formato de -S é -A
        if not rules or not any(f'-j {WHITELIST_CHAIN}' in r for r in rules):
            logging.info(f"Inserindo salto para '{WHITELIST_CHAIN}' no topo da chain '{chain}'...")
            run_command(['sudo', 'iptables', '-I', chain, '1', '-j', WHITELIST_CHAIN])

    # 3. Popular a chain de whitelist
    logging.info(f"Atualizando regras da chain '{WHITELIST_CHAIN}'...")
    config = load_config()
    whitelist_ips = config.get('whitelist_ips', [])
    run_command(['sudo', 'iptables', '-F', WHITELIST_CHAIN]) # Limpa para garantir estado fresco
    
    if whitelist_ips:
        for ip in whitelist_ips:
            run_command(['sudo', 'iptables', '-A', WHITELIST_CHAIN, '-s', ip, '-j', 'ACCEPT'])

def flush_last_run_rules():
    """Remove as regras de portas gerenciadas da última execução."""
    logging.info(f"--- Removendo regras da última execução a partir de {LAST_RULES_FILE} ---")
    if not os.path.exists(LAST_RULES_FILE):
        logging.warning(f"Arquivo '{LAST_RULES_FILE}' não encontrado. Nenhuma regra para remover.")
        return

    with open(LAST_RULES_FILE, 'r') as f:
        rules = f.readlines()
        for rule_str in reversed(rules):
            if not rule_str.strip(): continue
            # Converte o comando de inserção/adição para um de deleção
            delete_command = rule_str.strip().replace(' -I ', ' -D ').replace(' -A ', ' -D ').split()
            # Remove o número da linha para o comando de deleção se for o caso
            if delete_command[3].isdigit():
                del delete_command[3]
            run_command(delete_command)
    
    clear_last_rules_file()
    logging.info("Regras da última execução removidas com sucesso.")

def manage_ports(action):
    """Aplica regras de ACCEPT ou DROP para as portas gerenciadas."""
    logging.info(f"--- Iniciando '{action}' para as portas gerenciadas ---")
    flush_last_run_rules()
    
    config = load_config()
    managed_ports = config.get('managed_ports', [])
    never_block_ports = {str(p) for p in config.get('never_block_ports', [])}
    iptables_action = 'ACCEPT' if action == 'open' else 'DROP'

    if not managed_ports:
        logging.warning("Nenhuma porta gerenciada encontrada em config.yml.")
        return

    logging.info(f"--- Aplicando regras de '{iptables_action}' para as portas ---")
    for port in sorted(list(set(managed_ports)), reverse=True):
        port_str = str(port)
        if port_str in never_block_ports:
            logging.info(f"Ignorando porta da lista 'never_block_ports': {port_str}")
            continue

        for chain in ['INPUT', 'FORWARD']:
            # Inserir na posição 2, logo após o salto para a whitelist
            rule = ['sudo', 'iptables', '-I', chain, '2', '-p', 'tcp', '--dport', port_str, '-m', 'comment', '--comment', RULE_COMMENT, '-j', iptables_action]
            run_command(rule)
            record_rule(rule)
    
    logging.info(f"Regras de '{action}' aplicadas com sucesso.")

def backup_rules():
    """Salva as regras atuais do iptables em um arquivo."""
    logging.info(f"--- Fazendo backup das regras para {BACKUP_FILE} ---")
    try:
        with open(BACKUP_FILE, 'w') as f:
            subprocess.run(['sudo', 'iptables-save'], check=True, text=True, stdout=f)
        logging.info(f"Backup salvo em '{BACKUP_FILE}'.")
    except Exception as e:
        logging.error(f"Falha ao criar backup: {e}")

def restore_rules():
    """Restaura as regras do iptables a partir de um arquivo de backup."""
    logging.info(f"--- Restaurando regras a partir de {BACKUP_FILE} ---")
    if not os.path.exists(BACKUP_FILE):
        logging.error(f"Arquivo de backup '{BACKUP_FILE}' não encontrado.")
        return
    try:
        with open(BACKUP_FILE, 'r') as f:
            run_command(['sudo', 'iptables-restore', '--noflush'], stdin_file=f)
        logging.info("Regras restauradas com sucesso.")
    except Exception as e:
        logging.error(f"Falha ao restaurar regras: {e}")

def main():
    """Função principal que processa os argumentos da linha de comando."""
    setup_base_firewall()

    if len(sys.argv) == 1:
        manage_ports('block')
    elif sys.argv[1] == '-l':
        manage_ports('open')
    elif sys.argv[1] == '-f':
        flush_last_run_rules()
    elif sys.argv[1] == '-b':
        backup_rules()
    elif sys.argv[1] == '-r':
        restore_rules()
    else:
        print("Uso: python3 fw.py [-l | -f | -b | -r]")
        print("  (sem argumento): Bloqueia as portas do config.yml")
        print("  -l: Libera as portas do config.yml para acesso externo")
        print("  -f: Remove as regras aplicadas pelo script na última execução")
        print("  -b: Cria um backup das regras atuais do iptables")
        print("  -r: Restaura as regras a partir do backup")
        sys.exit(1)

if __name__ == '__main__':
    main()
