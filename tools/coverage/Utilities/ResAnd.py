import os
import shutil
import getopt
import sys


dir = ".\\input"
output = ".\\output.txt"
filecount = 0
modules = {}
basicblocks = {}
	


#Conf
def help():
	print "Possible arguments: GenBpFiles.py [-h] [-d DIR] [-o FILE]"
	print " -h      Prints this message to you"
	print " -d DIR  Directory that contains coverage files"
	print " -o FILE Result file"
	
	
try:                                
	opts, args = getopt.getopt(sys.argv[1:], "hd:o:", [])
except:
	help()
	sys.exit()
for opt, arg in opts:
	if opt in("-h"):
		help()
		sys.exit()
	if opt in("-o"):
		output = arg
	if opt in("-d"):
		dir = arg	

#Reading input
for fname in os.listdir(dir):
	print "File %s" % (dir + "/" + fname)
	f = open(dir + "/" + fname)
	
	#module list
	line = f.readline()
	modules = {}
	while line != "" and line[2] != "|":
		moduleName = line[:line.find("|")].lower()
		moduleCode = line[line.find("|")+1:line.find("|")+3]
		modules[moduleCode] = moduleName
		if moduleName not in basicblocks:
			basicblocks[moduleName] = {}
		line = f.readline()
		
	#basicblock
	while line.strip() != "":
		moduleCode = line[0:2]
		bb = line[3:11]
		moduleName = modules[moduleCode].lower()
		if bb not in basicblocks[moduleName]:
			basicblocks[moduleName][bb] = 1
		else:
			basicblocks[moduleName][bb] += 1
		line = f.readline()
	filecount += 1
	f.close()
		
print "Calculating results"
#Output
file = open(output, 'w')
#modules
count = 0
for x in basicblocks:
	file.write("%s|%02X\n" % (x, count))
	count += 1
#basic blocks
count = 0
for x in basicblocks:
	for y in basicblocks[x]:
		if basicblocks[x][y] == filecount:
			file.write("%02X|%s\n" % (count, y))
	count += 1
file.close()
	