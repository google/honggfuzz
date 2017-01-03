import os
import getopt
import sys
import subprocess
from winappdbg import Debug, Crash, win32, HexDump
from time import time
from winappdbg.util import MemoryAddresses

class Coverage:
	verbose = False
	bbFiles = {}
	bbFilesBreakpints = []
	bbFilesData = {}
	bbOriginalName = {}
	modules = []
	fileOutput = None
		
	#Construct
	def __init__(self):
		self.debugger = Debug( bKillOnExit = True )
		
	def setVerbose(self, val):
		self.verbose = val
		
	#cuts after .
	def cutDot(self, input):
		if (input.find(".") == -1):
			return input
		return input[0:input.find(".")]

	#load basic blocks
	def loadBB(self, baseBbDir):
		self.bbFiles = {}
		count = 0
		print "baseBbDir:"+baseBbDir
		for bbFile in os.listdir(baseBbDir):
			print "bbFile:" + bbFile
			f = open(baseBbDir + "/" + bbFile, "r")
			fname = f.readline().strip().lower()
			#fname = f.readline().strip()
			fnameOrig = fname
			if ".dll" not in fname and ".exe" not in fname:  #Stupid hack to avoid problems in loading libs with other extensions then .dll
				fname = self.cutDot(fname) + ".dll"
			self.bbOriginalName[fname] = fnameOrig
			self.bbFiles[fname] = count
			self.bbFilesBreakpints.append({})
			rvaHighest = 0
			for line in f:
				try:
					rva = int(line[0:8], 16)
					val = int(line[18:20], 16)
					self.bbFilesBreakpints[count][rva] = val
					if rva > rvaHighest:
						rvaHighest = rva
				except Exception:
					continue
			self.bbFilesData[fname] = [rvaHighest + 10, count]
			if self.verbose:
				print "Loaded breakpoints for %s with index %02X" % (fname, count)
			count += 1
			f.close()
	
	#Register module (original exe image or dll)
	def registerModule(self, filename, baseaddr):
		filename = filename.lower()
		if ".dll" not in filename and ".exe" not in filename:  #Stupid hack to avoid problems in loading libs with other extensions then .dll
			filename = self.cutDot(filename) + ".dll"
		if filename not in self.bbFiles:
			return
		if self.verbose:
			print "  Image %s has breakpoints defined" % filename
		self.modules.append([baseaddr,baseaddr+self.bbFilesData[filename][0], self.bbFilesData[filename][1]])
		if self.verbose:
			print "  Image has breakpoints from %08X to %08X with index %02X" % (baseaddr,baseaddr+self.bbFilesData[filename][0],self.bbFilesData[filename][1])
		
	#Handle a breakpoint
	def breakpoint(self, location):
		index = None
		for i in xrange(len(self.modules)):
			if location>=self.modules[i][0] and location<=self.modules[i][1]:
				index = i
				break
		if index == None:
			return None	
		rva = location - self.modules[index][0]
		index = self.modules[index][2]
		if rva not in self.bbFilesBreakpints[index]:
			return None
		self.fileOutput.write("%02X|%08X\n" % (index, rva))
		return self.bbFilesBreakpints[index][rva]
		
	def startFileRec(self, filename):
		self.modules = []
		self.fileOutput = open(filename, "w")
		for image in self.bbFiles:
			self.fileOutput.write("%s|%02X\n" % (self.bbOriginalName[image], self.bbFiles[image]))
		
	def endFileRec(self):
		self.fileOutput.close()		
	
	#Start program
	def start(self, execFile, waitTime = 6, recFilename = "output.txt", kill = True):	
		self.startFileRec(recFilename)
		mainProc = self.debugger.execv( execFile, bFollow = True )
		event = None
		endTime = time() + waitTime
		while time() < endTime:
			if not mainProc.is_alive():
				break
			try:
				event = self.debugger.wait(1000)
			except WindowsError, e:
				if e.winerror in (win32.ERROR_SEM_TIMEOUT, win32.WAIT_TIMEOUT):
					continue
				raise
			
			if event.get_event_code() == win32.LOAD_DLL_DEBUG_EVENT:
				module = event.get_module()
				if self.verbose:
					print "DLL %s loaded on base %08X" % (module.get_name(), module.get_base())
				self.registerModule(self.cutDot(module.get_name())+".dll", module.get_base())
			elif event.get_event_code() == win32.CREATE_PROCESS_DEBUG_EVENT:
				tmp = event.get_filename().split("\\")
				modName = tmp[len(tmp)-1]
				if self.verbose:
					print "Process %s loaded on base %08X" % (modName, event.raw.u.CreateProcessInfo.lpBaseOfImage)
				self.registerModule(modName,event.raw.u.CreateProcessInfo.lpBaseOfImage)
			elif event.get_event_code() == win32.EXCEPTION_DEBUG_EVENT and event.get_exception_code() == win32.STATUS_BREAKPOINT:
				pc = event.get_thread().get_pc()-1
				val = self.breakpoint(pc)
				if val != None:
					event.get_process().write(pc, chr(val))
					event.get_thread().set_pc(pc)
					endTime = time() + waitTime
					
			try:
				self.debugger.dispatch()
			except:
				pass
			finally:
				self.debugger.cont()
		self.endFileRec()
		if kill:
			self.kill()
		
		
	#Kill processes
	def kill(self):
		pids = self.debugger.get_debugee_pids()		
		self.debugger.detach_from_all( True )	
		for pid in pids:				
			try:
				proc = self.debugger.system.get_process(pid)
				proc.kill()
			except:
				pass
			subprocess.call(["taskkill", "/f", "/pid", str(pid)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

		
if __name__ == "__main__":
	baseBbDir = ""
	waitTime = 5
	resultFile = ""
	verbose = False

	def help():
		print "[Usage]: StartProcess.py [-h] [-b DIR] [-f FILE] [-T SEC] [-v] ARGS"
		print " -h          Prints this message to you"
		print " -b DIR      set the location where generator looks for breakpoint files"	
		print " -f FILE     set the location where the results are written"
		print " -t SEC      how long to keep running after last breakpoint"
		print " -v          script shows some information"
	
	try:                                
		opts, args = getopt.getopt(sys.argv[1:], "he:b:f:t:v")
		if args == None or len(args) == 0:
			raise "No arguments"
	except:
		help()
		sys.exit()
	for opt, arg in opts:
		if opt in("-h"):
			help()
			sys.exit()
		if opt in("-b"):
			baseBbDir = arg
		if opt in("-f"):
			resultFile = arg	
		if opt in("-t"):
			waitTime = int(arg)
		if opt in("-v"):
			verbose = True
	
	cov = Coverage()
	cov.setVerbose(verbose)
	cov.loadBB(baseBbDir)
	cov.start(args, waitTime, resultFile)
	cov.kill()