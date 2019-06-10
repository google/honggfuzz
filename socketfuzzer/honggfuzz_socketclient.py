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
        if n == 8:
            # heap buffer overflow
            data = "FFFFFF"

        #print "  Send: " + str(data)
        return self.sendToSocket(data)


def sendResp(targetSocketRes, hfSocket):
    if not targetSocketRes:
        print "  ! Server down. Send: bad!"
        hfSocket.send("bad!")
    else:
        hfSocket.send("okay")


def auto(pid):
    print "Auto Test"
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
    print "Test: 1 - expecting first new BB"
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
    print "Test: 2 - expecting second new BB"
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
    print "Test: 3 - repeat second msg, expecting no new BB"
    targetSocket.sendFuzz(2)
    sendResp(ret, hfSocket)
    ret = hfSocket.recv()
    if ret == "Fuzz":
        print "  ok: " + ret
    else:
        print "  nok: " + ret
        return

    print ""
    print "Test: 4 - crash stack, expect new BB, then crash notification"
    targetSocket.sendFuzz(6)
    sendResp(ret, hfSocket)
    # first, a new BB is detected
    ret = hfSocket.recv()
    if ret == "New!":
        print "  ok: " + ret
    else:
        print "  nok: " + ret
        return
    # this leads to a crash
    ret = hfSocket.recv()
    if ret == "Cras":
        print "  ok: " + ret
    else:
        print "  nok: " + ret
        return
    # after the crash, the target should have been restarted, and
    # we are ready to fuzz again
    ret = hfSocket.recv()
    if ret == "Fuzz":
        print "  ok: " + ret
    else:
        print "  nok: " + ret
        return

    print ""
    print "Test: 5 - resend second, expecting no new BB"
    targetSocket.sendFuzz(2)
    sendResp(ret, hfSocket)
    ret = hfSocket.recv()
    if ret == "Fuzz":
        print "  ok: " + ret
    else:
        print "  nok: " + ret
        return

    print ""
    print "Test: 6 - send three, expecting new BB"
    targetSocket.sendFuzz(3)
    sendResp(ret, hfSocket)
    ret = hfSocket.recv()
    if ret == "New!":
        print "  ok: " + ret
    elif ret == "Fuzz":
        print "  okish: Should have been New!, but lets continue anyway"
    else:
        print "  nok: " + ret
        return

    if ret == "New!":
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

    # lets simulate that the server has become unresponsive for some reason.
    # as described in #253
    print ""
    print "Test: 8 - fake unresponsive server"
    hfSocket.send("bad!")
    ret = hfSocket.recv()
    if ret == "Fuzz":
        print "  ok: " + ret
    else:
        print "  nok: " + ret
        return

    print ""
    print "Test: 9 - send four again, no new BB"
    targetSocket.sendFuzz(4)
    sendResp(ret, hfSocket)
    ret = hfSocket.recv()
    if ret == "Fuzz":
        print "  ok: " + ret
    else:
        print "  nok: " + ret
        return

    # shut honggfuzz down
    hfSocket.send("halt")

    # this does not really work yet in honggfuzz.
    if (False):
        # lets make the server unresponsive
        print ""
        print "Test: 10 - real unresponsive server"
        targetSocket.sendFuzz(8)
        sendResp(ret, hfSocket)
        # we first have a new BB
        ret = hfSocket.recv()
        if ret == "New!":
            print "  ok: " + ret
        else:
            print "  nok: " + ret
            return
        
        print ""
        print "Test: 11 - send four again, no new BB"
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
