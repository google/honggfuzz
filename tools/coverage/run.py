# By riusksk
# Create: 2016-12-15
# Update: 2016-12-27

import os
import sys
import platform
import getopt
from subprocess import call

idaPro = 'D:\\IDA 6.8\\idaq.exe'
codeCov = os.getcwd()+"\\GenCoverageInfo.py" 
binDir = ""
bbDir = os.getcwd()+"\\BBFile"
sampleDir = ''
target = ''
nogen = 0

def help():
	print "[Usage]: python run.py [-h] [-i binDir] [-e execFile] [-d idaFile] [-s sampleDir]"
	print " --help(-h)	Prints help message"
	print " -i 		Target dir"
	print " -d 		idaq/idaq64 file path"
	print " -e		Target exec file"
	print " -s		Sample dir"
	print " --nogen 	No Generage BBFile and Breakpoint file"
	
try: 
	opts, args = getopt.getopt(sys.argv[1:], "hd:i:e:s:", ["help", "nogen"])
except Exception, e:
	help()
	print str(e)
	sys.exit()
	
for opt, arg in opts:
	if opt in("-h", "--help"):
		help()
		sys.exit()
	if opt in("-e"):
		execfile = arg
		target = execfile[execfile.rfind("\\")+1:-4].replace(' ','')  # Program Name
		bbDir += "\\"+target
		if not os.path.exists(bbDir):
			os.makedirs(bbDir)	
	if opt in("-i"):
		binDir = arg
	if opt in("-d"):
		idaPro = arg
	if opt in("-s"):
		sampleDir = arg
	if opt in ("--nogen"):
		nogen = 1

if(nogen == 0 and binDir):
	
	print "[Step 1]: Generage Code Coverage File"
	
	for root, subFolder, files in os.walk(binDir):
		sysstr = platform.system()
		if(sysstr == "Windows"):
			magic = 'MZ'	# PE
			count = 2
		elif(sysstr == "Linux"):
			magic = "\x7F\x45\x4C\x46"	# ELF
			count = 4
		elif(sysstr == "Darwin"):
			magic = "\xCF\xFA\xED\xFE"  # Mach-O x64
			count = 4
		else:
			print "Only Support Windows/Linux/MacOS !!!"
			sys.exit()
			
		for item in files:
			fname = os.path.join(binDir, root, item)
			f=open(fname, "rb")
			if f.read(count) == magic:
				print "Analysing '%s'" % fname
				call([idaPro, '-S"' + codeCov + '"', '-A', fname])				
			f.close()

	if(platform.system() == "Windows"):
		os.system("move "+os.getcwd()+"\\BBFile\\*.bb "+os.getcwd()+"\\BBFile\\"+target)
	else:
		os.system("mv ./BBFile/*.bb ./BBFile/"+target)
	
	print "[Step 2]: Generage Breakpoint File"
	print "python GenBpFiles.py -i \"" + binDir + "\" -b " + bbDir + "\""
	os.system("python GenBpFiles.py -i \"" + binDir + "\" -b " + bbDir + "\"")
	
elif(nogen == 0):
	print "[*] No Set Bin Dir !!!"
	help()
	sys.exit()

if execfile and sampleDir:
	print "[Step 3]: Start Program File"
	if not os.path.exists(os.getcwd()+"./result/"+target):
			os.makedirs(os.getcwd()+"./result/"+target)
	if "\\" not in sampleDir[-1]:
		sampleDir = sampleDir + "\\"
	for root, subFolder, files in os.walk(sampleDir):
		for item in files:
			os.system("python StartProcess.py -v -f \"./result/"+target +'/'+ item + ".txt\"" + " -b \"" + bbDir + "\" \"" + execfile + "\" \"" + sampleDir + item+"\"")
else:
	print "No Samples !!!"
	sys.exit()

print "[Step 4]: Analysing Code Coverage"
os.system("python Analyze.py -b \""+bbDir+"\" -i ./result/" + target + "-o "+target+"_output.txt")



	

	