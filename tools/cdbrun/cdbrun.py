#!/usr/bin/python
# -*- coding: UTF-8 -*-

import subprocess
import os
import shutil
import sys
import time
import psutil
from datetime import datetime

class cdbfuzz:
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
		#cdb加载进程调试
		#cmd = cdblocation+' '+'-c ".logopen '+crashdir+'temp.log;g;g;r;kv;.logclose '+crashdir+'temp.log" '+program+' '+input_file
		
		#直接启动，设置cdb为默认调试器
		cmd = '"' + program + '" "' + input_file + '"'
		#print "[+] Start Process => " + cmd
		process = subprocess.Popen(cmd)
		return process
		
	def kill(self,proc_obj):
		proc_obj.terminate()
		
	def wascrash(self):#Did the prog. crash last time ??
		'''
		#cdb 附加调试输出日志的崩溃检测 
		log = open(crashdir+'temp.log').read()
		if ("Access violation - code" in log) or ("divide-by-zero") in log:
			return True
		'''	
		
		#当cdb为默认调试器，检测cdb.exe进程是否存在来监控崩溃
		ret = os.system("taskkill /F /IM cdb.exe 2>nul")
		if 0 == ret:
			return True
		else:
			return False
	
	def dumpcrash(self,crash_filename):
		print "[+] Dump Crash File !"
		prog = program.split('\\')[-1:][0]
		shutil.copyfile(crash_filename, crashdir+prog+'_'+crash_filename.split('\\')[-1:][0])
	
	def check(self, proc, file):
		begin = time.time()
		while 1:	
			if self.wascrash() == True:	
				print "[+] Crashed"
				self.dumpcrash(file)
				return
			elif (time.time() - begin) > timeout:
				self.kill(proc)
				return
			else:
				continue
				
timeout = 5
'''
if len(sys.argv) < 3:
	print "[Usage]: python cdbfuzzer.py <program> <file/dir> [timeout]"
	sys.exit()
else:
	program = sys.argv[1]
	input = sys.argv[2]
if len(sys.argv) == 4:
	timeout = sys.argv[3]
'''
cdblocation = "C:\\Program Files\\Debugging Tools for Windows (x64)\\cdb.exe"
program = "C:\\Program Files (x86)\\Adobe\Acrobat DC\\Acrobat\\Acrobat.exe"
input = "C:\\Users\\Administrator\\Desktop\\afl-tiff"
#input = "C:\\Users\\Administrator\\Desktop\\crash.tif"
crashdir = "./"
fuzz = cdbfuzz(program,crashdir,cdblocation)

if os.path.isdir(input):
	if input[-1] != '\\':
		input+='\\'
	dir = os.listdir(input)
	for file in dir:
		print "[+] Test " + file
		proc = fuzz.startapp(input+file)
		fuzz.check(proc, input+file)

else:
	proc = fuzz.startapp(input)
	fuzz.check(proc, input)

print "Test End !"		


