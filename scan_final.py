from tkinter import *
from tkinter.ttk import *
import time
import threading
import tkinter as tk
from tkinter import ttk

import psutil
import re
import hashlib
import os, signal
from time import sleep
from tqdm import tqdm


import time
import hashlib

from send2trash import send2trash
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class Watcher:
    DIRECTORY_TO_WATCH = "/root"
    DIRECTORY_TO_WATCH2 = "/media"

    def __init__(self):
        self.observer = Observer()

    def run(self):
        event_handler = Handler()
        self.observer.schedule(event_handler, self.DIRECTORY_TO_WATCH, recursive=True)
        self.observer.schedule(event_handler, self.DIRECTORY_TO_WATCH2, recursive=True)
        self.observer.start()
        try:
            while True:
                time.sleep(5)
        except:
            self.observer.stop()
            print("Error")

        self.observer.join()


class Handler(FileSystemEventHandler):

    @staticmethod
    def on_any_event(event):
        g = open("hash2.txt", "r")
        mal_compare = g.read()
        if event.is_directory:
            return None




        elif event.event_type == 'created':
            # Take any action here when a file is first created.
            
            Label(tab2,text="Received created event in - %s." % event.src_path).pack(pady=5)
            
            print("Received created event in - %s." % event.src_path)
            if os.path.exists(event.src_path) and os.path.isfile(event.src_path) and os.access(event.src_path, os.X_OK):

                f = open(event.src_path, "rb")
                
                # e=os.system("find event.src_path -type f -executable")
                # print(e)
                result = hashlib.sha256(f.read())
                # print(result.hexdigest() )
                if result.hexdigest() == mal_compare:
                    Label(tab2,text="1 malware file found").pack(pady=5)
                    Label(tab2,text="path: %s " % event.src_path).pack(pady=5)
                    send2trash(event.src_path)
                    Label(tab2,text="File Deleted").pack(pady=5)
                    print("1 malware file found")
                    print("path: %s " % event.src_path)
                    
                    print("File Deleted")
                    # os.system("mv event.src_path ~/Trash")

        elif event.event_type == 'modified':
            # Taken any action here when a file is modified.s
            
            Label(tab2,text="Received modified event in - %s." % event.src_path).pack(pady=5)
            print("Received modified event in - %s." % event.src_path)
            if os.path.exists(event.src_path) and os.path.isfile(event.src_path) and os.access(event.src_path, os.X_OK):
                f = open(event.src_path, "rb")
                var = StringVar()
                var.set("path: "+" "+ str(event.src_path))
                result = hashlib.sha256(f.read())
                if result.hexdigest() == mal_compare:
                    Label(tab2,text="1 malware file found").pack(pady=5)
                    Label(tab2,text=var2).pack(pady=5)
                    send2trash(event.src_path)
                    Label(tab2,text="File Deleted").pack(pady=5)
                    print("1 malware file found")
                    print("path: %s" % event.src_path)
                    #send2trash(event.src_path)
                    print("File Deleted")
                    # os.system("mv %event.src_path ~/Trash" %event.src_path)
                # print(result.hexdigest() )


def process_scan():
    
    while 1:
        #print("Scanning")
        Label(tab1,text="Scanning").pack(pady=10)
        # for i in tqdm(range(10)):
        #     sleep(1)
        g = open("hash.txt", "r")
        mal_compare = g.read()
        # Iterate over all running process
        p = ttk.Progressbar(tab1, orient=HORIZONTAL, length=300, mode="determinate", takefocus=True, maximum=100)
        p.pack(pady=5)
        
        i=0
        for proc in psutil.process_iter():

            try:
                # for i in tqdm(len(psutil.process_iter())):

                # sleep(3)
                # Get process name & pid from process object.
                processName = proc.name()
                processID = proc.pid
                # output_file = open("output.txt", 'wb')
                # print(processName , ' ::: ', processID)
                # output_file.write("process")
                # output_file.write(processID)
                # f = open("/proc/%i/maps" % processID, "r")
                # print(f.read())
                # f.close()

                #p.step()
                i += 1
                p['value'] += 1
                time.sleep(0.01)
                tab1.update()

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
                            # print(result.hexdigest())
                            # print('chunk \n')
                            if result.hexdigest() == mal_compare:
                                var1 = StringVar()
                                var1.set(str(processName))
                                os.kill(processID, signal.SIGKILL)
                                Label(tab1,text="1 malware found").pack(pady=1)
                                Label(tab1,textvariable=var1).pack(pady=1)
                                Label(tab1,text="killed").pack(pady=1)
                                print("1 malware found")
                                print(processName)
                                print("killed")
                            break
                maps_file.close()
                mem_file.close()

            # output_file.close()

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        Label(tab1,text="Scanning Done Successfully").pack(pady=1)
        print("Scanning Done Successfully")
        sleep(10)
        p.destroy()

def file_scan():
    w = Watcher()
    w.run()
    

def close():
    root.destroy()
    


root = tk.Tk()
root.title("Tab Widget")
tabControl = ttk.Notebook(root)

tab1 = ttk.Frame(tabControl)
tab2 = ttk.Frame(tabControl)

tabControl.add(tab1, text='Running Process Scan')
tabControl.add(tab2, text='Files Scan')
tabControl.pack(expand=1, fill="both")

scrollbar = Scrollbar(tab1)
scrollbar.pack( side = RIGHT, fill = Y )
scrollbar1 = Scrollbar(tab2)
scrollbar1.pack( side = RIGHT, fill = Y )

Button(tab2,text="EXIT",command=close).pack(pady=20)
Button(tab1, text="EXIT", command=close).pack(pady=20)
t = threading.Thread(target=process_scan)
t2 = threading.Thread(target=file_scan)

t.start()
t2.start()


# i=0
# for i in range(100):
#     p.step()
#     i+=1
#     time.sleep(1)
#     tab1.update()

# ttk.Label(tab1,
#           text="Welcome to \
#           GeeksForGeeks").grid(column=0,
#                                row=0,
#                                padx=30,
#                                pady=30)
# ttk.Label(tab2,
#           text="Lets dive into the\
#           world of computers").grid(column=0,
#                                     row=0,
#                                     padx=30,
#                                     pady=30)

root.mainloop()










