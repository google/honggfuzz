import os
import shutil
import getopt
import sys


inputDir = ".\\input"
outputDir = ".\\output"
inputFile = ".\\result.txt"
modules = {}
basicblocks = {}
	


#Conf
def help():
	print "Possible arguments: GenBpFiles.py [-h] [-d DIR] [-o FILE]"
	print " -h      Prints this message to you"
	print " -d DIR  Directory that contains basicblocks files"
	print " -i FILE File that contains basicblocks to remove"
	print " -o DIR  Result directory"
	
	
try:                                
	opts, args = getopt.getopt(sys.argv[1:], "hd:i:o:", [])
except:
	help()
	sys.exit()
for opt, arg in opts:
	if opt in("-h"):
		help()
		sys.exit()
	if opt in("-d"):
		inputDir = arg
	if opt in("-i"):
		inputFile = arg	
	if opt in("-o"):
		outputDir = arg	
		
	
#input file
print "Reading input file %s" % inputFile
f = open(inputFile)	
#module list
line = f.readline()
modules = {}
while line != "" and line[2] != "|":
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
	moduleName = modules[moduleCode]
	if bb not in basicblocks[moduleName]:
		basicblocks[moduleName][bb] = 1
	else:
		basicblocks[moduleName][bb] += 1
	line = f.readline()
f.close()


#Modifying basicblocks
if not os.path.isdir(outputDir):
	os.makedirs(outputDir)
for fname in os.listdir(inputDir):
	f = open(inputDir + "/" + fname)
	
	moduleLine = f.readline()
	module = moduleLine.strip().lower()
	if len(basicblocks[module]) == 0:
		print "File %s remains unchanged" % fname
		f.close()
		shutil.copy2(inputDir + "/" + fname, outputDir + "/" + fname)
		continue
	
	print "Modifying %s" % fname
	#basicblock
	fout = open(outputDir + "/" + fname, "w")
	fout.write(moduleLine)
	line = f.readline()
	while line.strip() != "":
		bb = line[0:8]
		if bb not in basicblocks[module]:
			fout.write(line)
		line = f.readline()
	f.close()
	fout.close()