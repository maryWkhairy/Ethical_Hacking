import psutil
import re
import hashlib
import os, signal
from time import sleep
from tqdm import tqdm

while 1:
    print("Scanning")
    for i in tqdm(range(10)):
        sleep(1)
    g = open("hash.txt", "r")
    mal_compare = g.read()
    # Iterate over all running process
    for proc in psutil.process_iter():
    
        try:
            # for i in tqdm(len(psutil.process_iter())):
    
            # sleep(3)
            # Get process name & pid from process object.
            processName = proc.name()
            processID = proc.pid
            # output_file = open("output.txt", 'wb')
            #print(processName , ' ::: ', processID)
            # output_file.write("process")
            # output_file.write(processID)
            # f = open("/proc/%i/maps" % processID, "r")
            # print(f.read())
            # f.close()
    
            maps_file = open("/proc/%i/maps" % processID, 'r')
            mem_file = open("/proc/%i/mem" % processID, 'rb', 0)
    
            for line in maps_file.readlines():  # for each mapped region
                m = re.match(r"([0-9A-Fa-f]+)-([0-9A-Fa-f]+) (r-x)", line)
                # print(m)
                if m != None:
                    if m.group(3) == 'r-x':  # if this is a readable region
                        # print(".........................")
                        # print(line)
    
                        start = int(m.group(1), 16)
                        end = int(m.group(2), 16)
                        mem_file.seek(start)  # seek to region start
                        chunk = mem_file.read(end - start)  # read region contents
                        # output_file.write(chunk)  # dump contents to standard output
                        # output_file.write('\n')
                        # print(chunk)
                        # print("encoded string: ",chunk.encode())
    
                        result = hashlib.sha256(chunk)
                        #print(result.hexdigest())
                        # print('chunk \n')
                        if result.hexdigest() == mal_compare:
                            os.kill(processID, signal.SIGKILL)
                            print("1 malware found")
                            print(processName)
                            print("killed")
                        break
            maps_file.close()
            mem_file.close()
    
        # output_file.close()
    
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    
    print("Scanning Done Successfully")
    sleep(10)
    
    
