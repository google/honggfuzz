import requests
import time
import string
import os.path
import urllib2
import sys
import getopt
from time import gmtime, strftime
 
 
#variables
class Downloader:
    extension = "pdf"
    signature = [0x25, 0x50, 0x44, 0x46]
    searchChars = ['a', 'a']
    outputDir = "downloaded_"
    downloaded = []
    successCount = 0
    maxPerSearch = 500
    last = 0
    lastStatus = 0
     
     
    def loadArguments(self, argv):
        options, rem = getopt.getopt(argv, 'x:s:q:o:m:', ['extension=', 'signature=', 'search=', 'output=', 'max='])
        for opt, arg in options:
            if opt in ('-x'):
                self.extension = arg
            elif opt in ('-s'):
                self.signature=[]
                for x in range(len(arg)/2):
                    self.signature.append(int(arg[(x*2):(x*2+2)], 16))
            elif opt in ('-q'):
                self.searchChars=[]
                for x in range(len(arg)):
                    self.searchChars.append(arg[x])
            if opt in ('-o'):
                self.outputDir = arg
            if opt in ('-m'):
                self.maxPerSearch = int(arg)
                 
    def currentStatusReport(self):
        if len(self.downloaded) % 10 != 0 or len(self.downloaded) == self.lastStatus:
            return
        self.lastStatus = len(self.downloaded)
        if not os.path.isdir(self.outputDir + self.extension):
            print strftime("%Y-%m-%d %H:%M:%S", gmtime()) + " --- TOTAL: " + str(len(self.downloaded))+ "  DOWNLOADED: 0"
        else:
            print strftime("%Y-%m-%d %H:%M:%S", gmtime()) + " --- TOTAL: " + str(len(self.downloaded))+ "  DOWNLOADED: " + str(len(os.listdir(self.outputDir + self.extension)))
             
     
    def loadList(self):
        if os.path.isfile("list_" + self.extension + ".txt"): 
            with open("list_" + self.extension + ".txt") as f:
                for line in f:
                    self.downloaded.append(line.strip())
		if os.path.isdir(self.outputDir + self.extension):
			self.successCount = len(os.listdir(self.outputDir + self.extension))
                     
    def readStatus(self):
        if os.path.isfile("status" + self.extension + "_" + str(len(self.searchChars)) + ".txt"): 
            with open("status" + self.extension + "_" + str(len(self.searchChars)) + ".txt") as f:
                x = 0
                for line in f:
                    if x<len(self.searchChars):
                        self.searchChars[x] = line.strip()
                    x += 1
     
    def start(self):
        self.loadList()
        self.readStatus()
         
        self.search()
         
    def downloadFile(self, url):
        fDir=self.outputDir + self.extension
        local_file = None
        if not os.path.isdir(fDir):
            os.makedirs(fDir)
			             
        try:
            f = urllib2.urlopen(url, timeout=10)
             
            for x in range(len(self.signature)):
                if ord(f.read(1))!=self.signature[x]:
                    f.close()
                    raise          
 
            local_file=open("%s/file%08d.%s" % (fDir, self.successCount, self.extension), "wb")
            for x in range(len(self.signature)):
                local_file.write(chr(self.signature[x]))
            local_file.write(f.read())
            local_file.close()
            f.close()           
        except KeyboardInterrupt:
            raise
        except:
            if local_file != None:
                local_file.close()
            for x in xrange(10):
                try:
                    if os.path.isfile("%s/file%08d.%s" % (fDir, self.successCount, self.extension)): 
                        os.remove("%s/file%08d.%s" % (fDir, self.successCount, self.extension))
                    break
                except:
                    if x==9:
                        raise
                    time.sleep(1)
            return
        self.successCount += 1
         
    def signatureText(self):
        result = ""
        for x in range(len(self.signature)):
            result += "%0.2X" % self.signature[x]
        return result
         
    def searchCharsText(self):
        result = ""
        for x in range(len(self.searchChars)):
            result += self.searchChars[x]
        return result
         
    def search(self):
        if self.extension == None or self.extension == "":
            print "ERROR: No extension specified!"
            return         
         
        if len(self.signature) == 0:
            print "WARNING: No signature specified - THERE WILL BE LOT OF FALSE RESULTS :("
             
        print "Starting with search"
        print "---------------------"
        print "Extension: " + self.extension
        print "Signature: " + self.signatureText()
        print "Starting search base: " + self.searchCharsText()
        print "Output dir: " + self.outputDir + self.extension
        print "Max results per search: " + str(self.maxPerSearch)
         
        self.searchReal("")     
         
    def searchReal(self, chars):
        if len(chars) < len(self.searchChars):
            for char in string.ascii_lowercase:
                self.searchReal(chars + char)
            return
         
        for x in range(len(self.searchChars)):
            if ord(chars[x])<ord(self.searchChars[x]):
                return
                 
        for x in range(len(self.searchChars)):
            self.searchChars[x]='a'
         
        f = open("list_" + self.extension + ".txt", "a")                    
        f_s = open("status" + self.extension + "_" + str(len(self.searchChars)) + ".txt", "w")
        for x in range(len(chars)):
            f_s.write(chars[x]+"\n")
        f_s.close()
         
        num = 0
        blocked = True
        print '---' + chars + '---'
        while num < self.maxPerSearch:
            r = 0
            while True:
                try:
                    if num == 0:
                        r=requests.get('http://www.google.ee/search?hl=en&q=filetype%3A' + self.extension + '+' + chars + '&num=100&btnG=Google+Search')
                    else:
                        r=requests.get('http://www.google.ee/search?hl=en&q=filetype%3A' + self.extension + '+' + chars + '&num=100&start=' + str(num))
                    break
                except:
                    r=0
         
         
            pos=r.content.find('<a href="')
            while pos != -1:
                pos2_a=r.content.find('"', pos+16)
                pos2_b=r.content.find('&amp;', pos+16)
                if pos2_a == -1:
                    pos2 = pos2_b
                elif pos2_b == -1:
                    pos2 = pos2_a
                else:
                    pos2 = min (pos2_a, pos2_b)
                if pos2 == -1:
                    break;
                url = r.content[pos+16:pos2]
                if url.find('.google.') == -1 and url.startswith('http'):
                    blocked = False
                    if url not in self.downloaded:
                        self.downloadFile(url)
                        self.downloaded.append(url)
                        f.write(url + "\n")
                         
                pos_a=r.content.find('<a href="', pos+1)
                pos_b=r.content.find('a href="/url?q=', pos+1)
                if pos_a == -1:
                    pos = pos_b
                elif pos_b == -1:
                    pos = pos_a
                else:
                    pos=min(pos_a, pos_b)
                self.currentStatusReport()
            if len(self.downloaded)==self.last:
                if num == 0:
                    time.sleep(15)
                break
            else:
                self.last = len(self.downloaded)
            num = num + 100
            time.sleep(5)
        print "Total: " + str(len(self.downloaded))
        if blocked:
            print "Come on Google!!! You are arming my research when you block me! Will wait for 2 hours :("
            time.sleep(7200)
         
obj = Downloader()
obj.loadArguments(sys.argv[1:])
obj.start()