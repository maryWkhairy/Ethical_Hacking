
import hashlib
import re
import hashlib
from subprocess import check_output
name="python"
def get_pid(name):
    return int(check_output(["pidof","-s",name]))
pid=get_pid(name)
#print(pid)
hash_result = hashlib.sha256()

maps_file = open("/proc/%i/maps" % pid, 'r')
#print(maps_file.read())
mem_file = open("/proc/%i/mem" % pid, 'rb', 0)
output_file = open("hash.txt", 'wb')   
chunk="" 
for line in maps_file.readlines():  # for each mapped region
            m = re.match(r"([0-9A-Fa-f]+)-([0-9A-Fa-f]+) (r-xp)", line)
            #print(m)
            if m!=None:
                  if m.group(3) == 'r-xp':  # if this is a readable region
                         #print(".........................")
                         #print(line)
                         
                         start = int(m.group(1), 16)
                         end = int(m.group(2), 16)
                         mem_file.seek(start)  # seek to region start
                         chunk = mem_file.read(end - start)  # read region contents
                         #hash_result.update(chunk)
                         #output_file.write(chunk)  # dump contents to standard output
                         #output_file.write('\n')
                         #print(chunk)
                         #print("encoded string: ",chunk.encode())

                         result = hashlib.sha256(chunk)
                         print("Hash during running:")
                         print(result.hexdigest())
                         r=result.hexdigest()
                         output_file.write(r.encode())
                         #print("DONE")
                         #print('chunk \n')
                         
                         break
#result = hashlib.sha256(chunk)
#print(hash_result.hexdigest())
#r=result.hexdigest()
#output_file.write(r.encode())
#print("DONE")
maps_file.close()
mem_file.close()
	#output_file.close()
#SCRIPTPATH="$( cd -- "$(bash "$0")" >/dev/null 2>&1 ; pwd -P )"
output_file = open("hash2.txt", 'wb')
f = open("./malware_code.py", "rb")
result = hashlib.sha256(f.read())
print("Hash of file while not running:")
print(result.hexdigest())
#output_file.write("\n")

r=result.hexdigest()
output_file.write(r.encode())

print("DONE")





  