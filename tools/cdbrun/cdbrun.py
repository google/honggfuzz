import subprocess
import os
import shutil
import sys
import time
from datetime import datetime

class cdbrun:
	def __init__(self,app,crashd,debugger):
		if os.path.exists(app) == True & os.path.exists(crashd) == True & os.path.exists(debugger) == True:
			global program
			global crashdir
			global cdblocation
		else:
			print "[+] Please check all given paths"
			exit()
		program = app
		print "[+] Target application path =>",program
		crashdir = crashd
		print "[+] Crash Dir => ",crashdir
		cdblocation = debugger
		print "[+] Debugger path => ",cdblocation
	def startapp(self,input_file):
		cmd = cdblocation+' '+'-c ".logopen '+crashdir+'temp.log;g;g;r;kv;.logclose '+crashdir+'temp.log" '+program+' '+input_file
		process = subprocess.Popen(cmd)
		return process
	def kill(self,proc_obj):
		proc_obj.terminate()
	def wascrash(self):#Did the prog. crash last time ??
		log = open(crashdir+'temp.log').read()
		if ("Access violation - code" in log) or ("divide-by-zero") in log:
			return True
	def dumpcrash(self,crash_filename):
		prog = program.split('\\')[-1:][0]
		shutil.copyfile(crash_filename, crashdir+prog+'_'+datetime.now().strftime("%y-%m-%d-%H-%M")+"_"+crash_filename)

timeout = 2		
if len(sys.argv) < 3:
	print "[Usage]: python cdbrun.py <program> <file/dir> [timeout]"
	sys.exit()
else:
	program = sys.argv[1]
	input = sys.argv[2]
	
if len(sys.argv) == 4:
	timeout = sys.argv[3]

cdblocation = "C:\\Program Files\\Debugging Tools for Windows (x64)\\cdb.exe"
#program = "C:\\Program Files (x86)\\Adobe\Acrobat DC\\Acrobat\\Acrobat.exe"
#input = "C:\\Users\\Administrator\\Downloads\\pdf"
#input = "C:\\Users\\Administrator\\Desktop\\test.pdf"
crashdir = "./"
run = cdbrun(program,crashdir,cdblocation)

if os.path.isdir(input):
	if input[-1] != '\\':
		input+='\\'
	dir = os.listdir(input)
	for file in dir:
		proc = run.startapp(input+file)
		time.sleep(timeout)			
		run.kill(proc)				
		if run.wascrash() == True:	
			print "Crashed"
			run.dumpcrash(file)
else:
	proc = run.startapp(input)
	time.sleep(timeout)				
	run.kill(proc)					
	if run.wascrash() == True:		
		print "Crashed"
		run.dumpcrash(input) 

print "Test End !"		


