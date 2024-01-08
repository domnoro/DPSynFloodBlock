import sys
import subprocess
import time
from datetime import datetime, timedelta

def run_command(command):
    try:
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Erro ao executar o comando: {e}")

def main():
    if len(sys.argv) != 4:
        print("Uso: programa.py HH:MM:SS quantidade comando")
        print('Exemplo: python3 h_comando_generico_packet_limit.py 19:34:50 3 "curl 10.0.3.3" ')
        return
    
    start_time_str = sys.argv[1]
    quantity = int(sys.argv[2])
    command_to_run = ' '.join(sys.argv[3:])

    try:
        start_hour, start_minute, start_second = map(int, start_time_str.split(":"))
    except ValueError:
        print("Formato de hora inválido. Use HH:MM:SS")
        return

    start_time = datetime.now().replace(hour=start_hour, minute=start_minute, second=start_second, microsecond=0)

    while quantity > 0:
        if datetime.now() >= start_time:
            run_command(command_to_run)
            quantity -= 1
        time.sleep(1)

if __name__ == "__main__":
    main()
