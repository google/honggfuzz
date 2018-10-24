#!/usr/bin/python
# Python3

import socket
import sys
import time
import random


class HonggfuzzSocket:
    def __init__(self, pid):
        self.sock = None
        self.pid = pid


    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        server_address = "/tmp/honggfuzz_socket"
        if self.pid is not None:
            server_address += "." + str(self.pid)
        print( 'connecting to %s' % server_address)

        try:
            self.sock.connect(server_address)
        except socket.error as msg:
            print ("Error connecting to honggfuzz socket: " + str(msg))
            sys.exit(1)


    def send(self, data):
        self.sock.sendall( str.encode(data) )


    def recv(self):
        return self.sock.recv(4).decode()


    def disconnect(self):
        self.sock.close()


class TargetSocket:
    def __init__(self):
        self.sock = None

    def testServerConnectionTcp(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = ('localhost', self.targetPort)

        try:
            sock.connect(server_address)
        except socket.error as exc:
            return False

        sock.close()

        return True


    def sendToSocket(self, data):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)

        host = 'localhost'
        port = 5001

        isOpen = False

        n = 0
        while isOpen is False:
            try:
                s.connect((host, port))
                isOpen = True
            except Exception as e:
                time.sleep(0.1)
                n += 1
                isOpen = False

            if n == 10:
                return False

        try:
            s.send( str.encode(data) )
        except Exception as e:
            print( "B: " + str(e))

        s.close()
        return True


    def sendFuzz(self, n):
        data = ""
        if n == 1:
            data = "AAAAAA"
        if n == 2:
            data = "BBBBBB"
        if n == 3:
            data = "CCCCCC"
        if n == 4:
            data = "DDDDDD"
        if n == 5:
            data = "EEEEEE"
        if n == 6:
            # stack buffer overflow
            data = "B" * 128
        if n == 7:
            # heap buffer overflow
            data = "C" * 128

        #print "  Send: " + str(data)
        return self.sendToSocket(data)



def sendResp(targetSocketRes, hfSocket):
    if not targetSocketRes:
        print "  ! Server down. Send: bad!"
        hfSocket.send("bad!")
    else:
        hfSocket.send("okay")



def auto(pid):
    print "Auto"

    hfSocket = HonggfuzzSocket(pid)
    targetSocket = TargetSocket()

    hfSocket.connect()


    print ""
    print "Test: 0 - initial"
    ret = hfSocket.recv()
    if ret == "Fuzz":
        print "  ok: " + ret
    else:
        print "  nok: " + ret
        return


    print ""
    print "Test: 1 - first new BB"
    ret = targetSocket.sendFuzz(1)
    sendResp(ret, hfSocket)
    ret = hfSocket.recv()
    if ret == "New!" or ret == "Fuzz":
        print "  ok: " + ret
    else:
        print "  nok: " + ret
        return
    ret = hfSocket.recv()
    if ret == "Fuzz":
        print "  ok: " + ret
    else:
        print "  nok: " + ret
        return


    print ""
    print "Test: 2 - second new BB"
    targetSocket.sendFuzz(2)
    sendResp(ret, hfSocket)
    ret = hfSocket.recv()
    if ret == "New!":
        print "  ok: " + ret
    else:
        print "  nok: " + ret
        return
    ret = hfSocket.recv()
    if ret == "Fuzz":
        print "  ok: " + ret
    else:
        print "  nok: " + ret
        return


    print ""
    print "Test: 3 - repeat second msg, no new BB"
    targetSocket.sendFuzz(2)
    sendResp(ret, hfSocket)
    ret = hfSocket.recv()
    if ret == "Fuzz":
        print "  ok: " + ret
    else:
        print "  nok: " + ret
        return

    print ""
    print "Test: 4 - crash stack"
    targetSocket.sendFuzz(6)
    sendResp(ret, hfSocket)
    ret = hfSocket.recv()
    if ret == "Cras":
        print "  ok: " + ret
    else:
        print "  nok: " + ret
        return
    ret = hfSocket.recv()
    if ret == "Fuzz":
        print "  ok: " + ret
    else:
        print "  nok: " + ret
        return

    print ""
    print "Test: 5 - resend second, no new BB"
    targetSocket.sendFuzz(2)
    sendResp(ret, hfSocket)
    ret = hfSocket.recv()
    if ret == "Fuzz":
        print "  ok: " + ret
    else:
        print "  nok: " + ret
        return

    print ""
    print "Test: 6 - send three, new BB"
    targetSocket.sendFuzz(3)
    sendResp(ret, hfSocket)
    ret = hfSocket.recv()
    if ret == "New!":
        print "  ok: " + ret
    else:
        print "  nok: " + ret
        return
    ret = hfSocket.recv()
    if ret == "Fuzz":
        print "  ok: " + ret
    else:
        print "  nok: " + ret
        return


    print ""
    print "Test: 7 - send four, new BB"
    targetSocket.sendFuzz(4)
    sendResp(ret, hfSocket)
    ret = hfSocket.recv()
    if ret == "New!":
        print "  ok: " + ret
    else:
        print "  nok: " + ret
        return
    ret = hfSocket.recv()
    if ret == "Fuzz":
        print "  ok: " + ret
    else:
        print "  nok: " + ret
        return


    print ""
    print "Test: 8 - send four again, no new BB"
    targetSocket.sendFuzz(4)
    sendResp(ret, hfSocket)
    ret = hfSocket.recv()
    if ret == "Fuzz":
        print "  ok: " + ret
    else:
        print "  nok: " + ret
        return


def interactive(pid):
    hfSocket = HonggfuzzSocket(pid)
    targetSocket = TargetSocket()

    hfSocket.connect()

    while(True):
        try:
            recv = hfSocket.recv()

            if recv == "Fuzz":
                # Send the bad data to the target
                i = input("--[ Send Msg #: ")
                #i = random.randint(0, 3)
                #sendFuzz(int(i))
                print "Send to target: " + str(i)
                if not targetSocket.sendFuzz(i):
                    print "Server down. Send: bad!"
                    hfSocket.send("bad!")
                else:
                    hfSocket.send("okay")

            elif recv == "New!":
                print ("--[ R Adding file to corpus...")
                # add the data you sent to the target to your input
                # corpus, as it reached new basic blocks

            elif recv == "Cras":
                print ("--[ R Target crashed")
                # target crashed, store the things you sent to the target

            elif recv == "":
                print("Hongfuzz quit, exiting too\n")
                break

            else:
                print ("--[ Unknown: " + str(recv))

        except Exception as e:
            print("Exception: " + str(e))



def main():
    mode = None
    pid = None

    if len(sys.argv) >= 2:
        if sys.argv[1] == "auto":
            mode = "auto"
        elif sys.argv[1] == "interactive":
            mode = "interactive"

    if len(sys.argv) >= 3:
        pid = int(sys.argv[2])
    else:
        print "honggfuzz_socketclient.py [auto/interactive] <pid>"

    if mode is "auto":
        auto(pid)
    elif mode is "interactive":
        interactive(pid)


main()
