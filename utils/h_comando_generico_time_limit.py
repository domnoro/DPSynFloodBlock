import sys
import os
import time
from datetime import datetime, timedelta

def run_command(command):
    try:
        os.system(command)
    except Exception as e:
        print(f"Erro ao executar o comando: {e}")

def main():
    if len(sys.argv) != 4:
        print("Uso: programa.py HH:MM:SS duracao_em_minutos 'comando'")
        print('Exemplo: python3 h_comando_generico_time_limit.py 19:30:20 1 "curl 10.0.3.3"')
        return
    
    start_time_str = sys.argv[1]
    duration_minutes = int(sys.argv[2])
    command_to_run = ' '.join(sys.argv[3:])

    try:
        start_hour, start_minute, start_second = map(int, start_time_str.split(":"))
    except ValueError:
        print("Formato de hora inválido. Use HH:MM:SS")
        return

    start_time = datetime.now().replace(hour=start_hour, minute=start_minute, second=start_second, microsecond=0)
    end_time = start_time + timedelta(minutes=duration_minutes)

    while datetime.now() < end_time:
        if datetime.now() >= start_time:
            run_command(command_to_run)
        time.sleep(1)
        if datetime.now() >= end_time:
            break

if __name__ == "__main__":
    main()
