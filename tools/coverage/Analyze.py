import os
import shutil
import getopt
import sys
import time

dir = ".\\result"
tmpDir = ".\\tmp"
output = ".\\output.txt"
bbDir = os.getcwd()+"\\BBFile"
BBcount = 0
totalBB = 0
modules = {}
basicblocks = {}
results = []

#Conf
def help():
	print "Possible arguments: Analyze.py [-h] [-b bbDir] [-i DIR] [-o FILE]"
	print " -h      	Prints this message to you"
	print " -b bbDir 	Directory that contains bb file"
	print " -i DIR  	Directory that contains coverage files"
	print " -o FILE 	Result file"
	
	
try:                                
	opts, args = getopt.getopt(sys.argv[1:], "hb:i:o:", [])
except:
	help()
	sys.exit()
for opt, arg in opts:
	if opt in("-h"):
		help()
		sys.exit()
	if opt in("-o"):
		output = arg
	if opt in("-i"):
		dir = arg	
	if opt in("-b"):
		bbDir = arg

#Create tmp dirs
if not os.path.exists(tmpDir + "0"):
	os.makedirs(tmpDir + "0")
if not os.path.exists(tmpDir + "1"):
	os.makedirs(tmpDir + "1")
		
#Prep
filelist = os.listdir(dir)
tmpCount = 0x1
		
#First pass through
lastTime = time.time()
for fname in filelist:
	f = open(dir + "\\" + fname)
	
	#module list
	line = f.readline()
	modules = {}
	while line != "" and line[2] != "|":
		#moduleName = line[:line.find("|")].lower()
		moduleName = line[:line.find("|")]
		moduleCode = line[line.find("|")+1:line.find("|")+3]
		modules[moduleCode] = moduleName
		if moduleName not in basicblocks:
			basicblocks[moduleName] = {}
		line = f.readline()
		
	#basicblock
	while line.strip() != "":
		moduleCode = line[0:2]
		bb = line[3:11]
		#moduleName = modules[moduleCode].lower()
		moduleName = modules[moduleCode]
		if bb not in basicblocks[moduleName]:
			basicblocks[moduleName][bb] = False
			BBcount += 1
		line = f.readline()
	f.close()

print "[*] Analyze Code Coverage ......"
# Get Total BB Count
for root, subFolder, files in os.walk(bbDir):
	for item in files:
		totalBB += len(open(bbDir+'\\'+item,'rU').readlines()) - 1
	
print "[*] FileCount: %d" % len(filelist)
print "[*] BasicBlocks: %d" % BBcount
print "[*] TotalBB: %d" % totalBB
print "[*] Coverage: %.1f" % ((float(BBcount)/totalBB)*100) + '%\n'

print "[*] Analyze Coverage File ......"
#Real analysis
freport = open(output, 'w')
srcDir = dir
destDir = tmpDir + "0"
while BBcount>0:
	best = 0;
	bestName = None	
	lastTime = time.time()
	
	#Find largest file
	for fname in filelist:
		if fname in results:
			continue
		size = os.path.getsize(srcDir + "/" + fname)
		if size > best:
			best = size
			bestName = fname			
			
	#Best coverage file
	f = open(srcDir + "/" + bestName)	
	best = 0
	#module list
	line = f.readline()
	modules = {}
	while line != "" and line[2] != "|":
		#moduleName = line[:line.find("|")].lower()
		moduleName = line[:line.find("|")]
		moduleCode = line[line.find("|")+1:line.find("|")+3]
		modules[moduleCode] = moduleName
		if moduleName not in basicblocks:
			basicblocks[moduleName] = {}
		line = f.readline()		
	#basicblock
	while line.strip() != "":
		moduleCode = line[0:2]
		bb = line[3:11]
		#moduleName = modules[moduleCode].lower()
		moduleName = modules[moduleCode]
		basicblocks[moduleName][bb] = True
		line = f.readline()
		best+=1		
	f.close()
			
	
	#Remove covered blocks
	for fname in filelist:
		f = open(srcDir + "/" + fname, "r")
		fout = open(destDir + "/" + fname, "w")	
		#module list
		line = f.readline()
		modules = {}
		while line != "" and line[2] != "|":
			fout.write(line)
			#moduleName = line[:line.find("|")].lower()
			moduleName = line[:line.find("|")]
			moduleCode = line[line.find("|")+1:line.find("|")+3]
			modules[moduleCode] = moduleName
			if moduleName not in basicblocks:
				basicblocks[moduleName] = {}
			line = f.readline()		
		#basicblock
		while line.strip() != "":
			moduleCode = line[0:2]
			bb = line[3:11]
			#moduleName = modules[moduleCode].lower()
			moduleName = modules[moduleCode]
			if not basicblocks[moduleName][bb]:
				fout.write(line)
			line = f.readline()			
		f.close()
		fout.close()
	
	BBcount -= best
	results.append(bestName)
	print "%d: %s covered %d basicblocks" % (len(results), bestName, best)
	freport.write("%s\n" % bestName)
	destDir = tmpDir + str(tmpCount)
	tmpCount = tmpCount ^ 0x1
	srcDir = tmpDir + str(tmpCount)

freport.close()
	