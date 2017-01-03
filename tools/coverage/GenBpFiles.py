import os
import shutil
import getopt
import sys

baseExecDir = os.getcwd()+"\\"
baseBbDir = ""

#Conf
def help():
	print "[Usage]: GenBpFiles.py [-h] [-i execDir] [-b bpfileDir]"
	print " -h Prints this message to you"
	print " -i DIR sets the location where the generator looks for exe and dll files"
	print " -b DIR set the location where generator looks for breakpoint files"
		
try:                                
	opts, args = getopt.getopt(sys.argv[1:], "hi:b:", ["help"])
except Exception, e:
	help()
	print str(e)
	sys.exit()
for opt, arg in opts:
	if opt in("-h"):
		help()
		sys.exit()
	if opt in("-i"):
		baseExecDir = arg
		#print arg
	if opt in("-b"):
		baseBbDir = arg		

#Load BB files
print "Loading all BB files"
bbFiles = {}
confFiles = {}
for bbFile in os.listdir(baseBbDir):
	f = open(baseBbDir + "\\" + bbFile, "r")
	fname = f.readline().strip()
	bbFiles[fname] = []
	confFiles[fname] = baseBbDir + "/" + bbFile
	f.close()
	
#Find files
print "Finding files to modify"
print "baseExecDir: " + baseExecDir
for root, subFolder, files in os.walk(baseExecDir):
	for item in files:
		#item = item.lower()
		if item in bbFiles:
			bbFiles[item].append(str(os.path.join(baseExecDir, root, item)))
			
#Any file not found
for fname in bbFiles:
	if len(bbFiles[fname]) == 0:
		print ">>>No file named '%s' was found" % fname
		del bbFiles[fname]
		del confFiles[f.readline().strip()]
	
#Lets start the modifications
for fname in bbFiles:
	for target in bbFiles[fname]:
		print "Modifying %s based of BB-s in %s" % (target, confFiles[fname])
		shutil.copyfile(target, target + "_original")
		f = open(confFiles[fname], "r")
		fa = open(target, "r+b")
		
		f.readline()
		for line in f:			
			try:
				offset = int(line[9:17], 16)
				fa.seek(offset)
				fa.write(chr(0xCC))
			except Exception:
				print line
			
		f.close()
		fa.close()
print "DONE"