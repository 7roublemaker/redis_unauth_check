import re 
import os 
import sys 
import time 
import socket 
import getopt 
import codecs 
import warnings
import threading 
import colorama 
colorama.init(autoreset=True)
warnings.filterwarnings("ignore")

# check IP format
def IP_check(ip_str): 
    if ip_str in blacklist: 
        print("\033[1;43m[-] Error: The target %s is in black list.\033[0m"%(ip_str)) 
        return False 
    ip_regex = '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' 
    if re.findall(ip_regex, ip_str)[0] == ip_str: 
        return True 
    print('\033[1;43m[-] Error: The format of IP %s is incorrect.\033[0m'%ip_str) 
    return False

# run the redis unauthrize accesss check
def check(t_target): 
    #IP_check(ip) 
    if ':' in t_target: 
        ip = t_target.split(':')[0] 
        port = t_target.split(':')[1] 
    else: 
        ip = t_target 
        port = 6379 
    if not IP_check(ip): 
        return False 
    try: 
        connect = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
        connect.settimeout(1) 
        connect.connect((ip,int(port))) 
        connect.send("info\r\n".encode("utf-8")) 
        data = connect.recv(1024) 
        if "version" in data.decode("utf-8"): 
            print("\033[1;41m[+] The target %s:%s may be vulnerable!\033[0m"%(ip, str(port))) 
            return data 
        else: 
            print("\033[1;40m[*] The target %s:%s may not be vulnerable!\033[0m"%(ip, str(port))) 
            return False 
        connect.close() 
    except Exception as e: 
        print("\033[1;43m[-] Error: The socket of %s with port %s has error!%s\033[0m"%(ip, str(port), e)) 
        return False

# read the targets file
def read_file(filename): 
    try: 
        file = open(filename, 'r').read().replace('\r','').replace('\t','').replace(' ','').split('\n') 
        return file 
    except Exception as e: 
        print('\033[1;43m[-] Error: Can not read %s.%s\033[0m'%(filename, e)) 
        exit()

# handle the input value      
def opt_handle(): 
    print("\033[1;40m[*] Handling the input value.\033[0m")
    host = False 
    port = False 
    file = False 
    thread_num = 10 
    try: 
        options,args = getopt.getopt(sys.argv[1:], "h:f:t:p:", ['host=', "file=", "thread=", "port="]) 
        for name, value in options: 
            if name in ('-h', '--host'): 
                #print(value) 
                host = value 
            elif name in ('-f', '--filename'): 
                #print(value) 
                filename = value 
                file = read_file(filename) 
            elif name in ('-t', '--tread'): 
                #print(value) 
                thread_num = int(value) 
            elif name in ('-p', '--port'): 
                #print(value) 
                port = value 
            else: 
                    print(usage) 
                    exit() 
    except Exception as e: 
        #print(e) 
        print(usage) 
        exit() 
    if host and file: 
        print('\033[1;43m[-] Error: Can not input host and file at the same time.\033[0m') 
        exit() 
    elif not host and not file: 
        print('\033[1;43m[-] Error: Please input the host or the name of targets file.\033[0m') 
        exit() 
    if host: 
        target = host 
        thread_num = 1 
    else: 
        target = file 
    return target, port, thread_num 

# write result to file
def write_to_file(vuln_redis):
    try: 
        outfilename = time.strftime("result/vuln_redis_%Y%m%d%H%M.csv") 
        file = codecs.open(outfilename, 'w', 'utf-8') 
        print('\033[1;40m[*] Writing result to %s.\033[0m' % outfilename) 
        file.write('IP,PORT,INFO\n') 
        for tmp in vuln_redis: 
            if ':' in tmp: 
                host = tmp.split(':')[0] 
                port = tmp.split(':')[1] 
            else: 
                host = tmp 
                port = '6379' 
            file.write(host+','+port+',"'+vuln_redis[tmp].decode('utf-8').replace('"','')+'"\n') 
        file.close() 
        print('\033[1;41m[+] Scan result saved in %s.\033[0m' % outfilename) 
    except Exception as e: 
        print('\033[1;43m[-] Error: Write result error.%s\033[0m'%(e)) 
        print('\033[1;43m[-] Please see the %s\033[0m'%log_filename)
        
if __name__ == "__main__":
    print(usage) 
    # handle input value
    target, port, thread_num = opt_handle() 
    # handle single target
    if isinstance(target,str): 
        if IP_check(target): 
            if port: 
                target = target + ':' + port  
                exp_redis_unauth(target) 
            else: 
                exp_redis_unauth(target) 
        exit() 
    elif len(target) < thread_num: 
        thread_num = len(target) 
    vuln_redis = {} 
    for t_target in target: 
        result = exp_redis_unauth(t_target) 
        if result is not False: 
            vuln_redis[t_target] = result
    write_to_file(vuln_redis)
