import subprocess
import sys
import logging
import yaml
import os

# --- Configuração ---
CONFIG_FILE = 'config.yml'
LOG_FILE = 'fw.log'
BACKUP_FILE = 'iptables.backup'
LAST_RULES_FILE = '.fw-last-rules.log'  # Arquivo para guardar as últimas regras aplicadas
RULE_COMMENT = 'managed-by-fw-script'  # Comentário para identificar nossas regras
EXEMPT_PORTS = {'22', '80', '443', '8080'}  # Portas que nunca serão gerenciadas

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
    """Executa um comando no shell, com opção de redirecionar stdin de um arquivo."""
    logging.info(f"Executando comando: {' '.join(command)}")
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
        logging.error(f"Erro ao executar comando: {' '.join(command)}")
        logging.error(f"Stderr: {e.stderr.strip()}")
        if 'Permission denied' in e.stderr:
            logging.error("Dica: O script precisa ser executado com privilégios de root (use 'sudo').")
        sys.exit(1)
    except FileNotFoundError:
        logging.error(f"Erro: 'iptables' não encontrado. Verifique se está instalado e no PATH.")
        sys.exit(1)

def record_rule(command):
    """Grava um comando de regra no arquivo de log de regras."""
    with open(LAST_RULES_FILE, 'a') as f:
        f.write(' '.join(command) + '\n')

def clear_last_rules_file():
    """Limpa o arquivo de log de regras."""
    if os.path.exists(LAST_RULES_FILE):
        os.remove(LAST_RULES_FILE)
    logging.info(f"Arquivo de regras '{LAST_RULES_FILE}' foi limpo.")

def load_config():
    """Carrega a configuração completa do arquivo config.yml."""
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = yaml.safe_load(f)
            logging.info(f"Configuração carregada de {CONFIG_FILE}")
            return config
    except FileNotFoundError:
        logging.error(f"Arquivo de configuração '{CONFIG_FILE}' não encontrado.")
        return {}
    except yaml.YAMLError as e:
        logging.error(f"Erro ao ler o arquivo YAML '{CONFIG_FILE}': {e}")
        return {}

def flush_rules():
    """Remove as regras aplicadas na última execução, lendo do arquivo de log."""
    logging.info(f"--- Iniciando remoção de regras a partir de {LAST_RULES_FILE} ---")
    if not os.path.exists(LAST_RULES_FILE):
        logging.warning(f"Arquivo '{LAST_RULES_FILE}' não encontrado. Nenhuma regra para remover.")
        return

    with open(LAST_RULES_FILE, 'r') as f:
        rules = f.readlines()
        for rule_str in reversed(rules):
            rule_str = rule_str.strip()
            if not rule_str:
                continue
            
            # Converte 'iptables -A/I ...' para 'iptables -D ...'
            delete_command = rule_str.replace(' -A ', ' -D ').replace(' -I ', ' -D ').split()
            # Remove o '1' de regras de inserção (-I CHAIN 1) para a deleção
            if len(delete_command) > 3 and delete_command[2] in ['INPUT', 'FORWARD'] and delete_command[3] == '1':
                del delete_command[3]

            logging.info(f"Removendo regra: {' '.join(delete_command)}")
            run_command(delete_command)
    
    clear_last_rules_file()
    logging.info("Regras da última execução removidas com sucesso.")

def manage_ports(action):
    """Aplica regras de ACCEPT ou DROP para as portas gerenciadas."""
    logging.info(f"--- Iniciando '{action}' para as portas gerenciadas ---")
    
    flush_rules() # Limpa regras antigas antes de aplicar novas

    config = load_config()
    managed_ports = config.get('managed_ports', [])
    whitelist_ips = config.get('whitelist_ips', [])
    iptables_action = 'ACCEPT' if action == 'open' else 'DROP'

    # 1. Aplicar whitelist com prioridade
    if whitelist_ips:
        logging.info("--- Aplicando regras de whitelist ---")
        for ip in whitelist_ips:
            logging.info(f"Permitindo acesso total para o IP/range: {ip}")
            rule_input = ['sudo', 'iptables', '-I', 'INPUT', '1', '-s', ip, '-m', 'comment', '--comment', RULE_COMMENT, '-j', 'ACCEPT']
            run_command(rule_input)
            record_rule(rule_input)

    # 2. Aplicar regras para as portas gerenciadas
    if not managed_ports:
        logging.warning("Nenhuma porta gerenciada encontrada em config.yml.")
        return

    logging.info(f"--- Aplicando regras de '{iptables_action}' para as portas ---")
    for port in managed_ports:
        port_str = str(port)
        if port_str in EXEMPT_PORTS:
            logging.info(f"Ignorando porta de exceção: {port_str}")
            continue

        logging.info(f"Aplicando regra '{iptables_action}' para a porta {port_str}")
        rule_input = ['sudo', 'iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', port_str, '-m', 'comment', '--comment', RULE_COMMENT, '-j', iptables_action]
        run_command(rule_input)
        record_rule(rule_input)
        rule_forward = ['sudo', 'iptables', '-A', 'FORWARD', '-p', 'tcp', '--dport', port_str, '-m', 'comment', '--comment', RULE_COMMENT, '-j', iptables_action]
        run_command(rule_forward)
        record_rule(rule_forward)
    
    logging.info(f"Regras de '{action}' aplicadas com sucesso.")

def backup_rules():
    """Salva as regras atuais do iptables em um arquivo."""
    logging.info(f"--- Iniciando backup das regras para {BACKUP_FILE} ---")
    try:
        with open(BACKUP_FILE, 'w') as f:
            subprocess.run(['sudo', 'iptables-save'], check=True, text=True, stdout=f)
        logging.info(f"Backup das regras do iptables salvo em '{BACKUP_FILE}'.")
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
    if len(sys.argv) == 1:
        manage_ports('block')
    elif sys.argv[1] == '-n':
        manage_ports('open')
    elif sys.argv[1] == '-f':
        flush_rules()
    elif sys.argv[1] == '-b':
        backup_rules()
    elif sys.argv[1] == '-r':
        restore_rules()
    else:
        print("Uso: python3 fw.py [-n | -f | -b | -r]")
        print("  (sem argumento): Bloqueia as portas do config.yml")
        print("  -n: Libera as portas do config.yml para acesso externo")
        print("  -f: Remove as regras aplicadas pelo script na última execução")
        print("  -b: Cria um backup das regras atuais do iptables")
        print("  -r: Restaura as regras a partir do backup")
        sys.exit(1)

if __name__ == '__main__':
    main()
