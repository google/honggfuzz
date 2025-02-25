#!/usr/bin/python3

import socket
import sys
import time

class HonggfuzzSocket:
    def __init__(self, pid):
        self.sock = None
        self.pid = pid


    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        server_address = "/tmp/honggfuzz_socket"
        if self.pid is not None:
            server_address += "." + str(self.pid)
        print('connecting to %s' % server_address)

        try:
            self.sock.connect(server_address)
        except socket.error as msg:
            print("Error connecting to honggfuzz socket: " + str(msg))
            sys.exit(1)


    def send(self, data):
        self.sock.sendall(str.encode(data))


    def recv(self):
        return self.sock.recv(4).decode()


    def disconnect(self):
        self.sock.close()


class TargetSocket:
    def __init__(self):
        self.sock = None


    def test_svr_tcp_connection(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sever_addr = ('localhost', 5001)

        try:
            sock.connect(sever_addr)
        except socket.error as exc:
            return False

        sock.close()
        return True


    def send_to_socket(self, data):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        server_addr = ('localhost', 5001)
        max_retries = 10
        for _ in range(max_retries):
            try:
                sock.connect(server_addr)
                break
            except Exception as e:
                time.sleep(0.1)

        try:
            sock.send(str.encode(data))
        except Exception as e:
            print("B: " + str(e))

        sock.close()
        return True


    def sendfuzz(self, n):
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

        return self.send_to_socket(data)


def sendresp(target_socket_res, hfuzz_socket):
    if not target_socket_res:
        print("  ! Server down. Send: bad!")
        hfuzz_socket.send("bad!")
    else:
        hfuzz_socket.send("okay")


def auto(pid):
    print("Auto Test")
    hfuzz_socket = HonggfuzzSocket(pid)
    target_socket = TargetSocket()
    hfuzz_socket.connect()

    print()
    print("Test: 0 - initial")
    ret = hfuzz_socket.recv()
    if ret == "Fuzz":
        print("  ok:", ret)
    else:
        print("  nok:", ret)
        return

    print()
    print("Test: 1 - expecting first new BB")
    ret = target_socket.sendfuzz(1)
    sendresp(ret, hfuzz_socket)
    ret = hfuzz_socket.recv()
    if ret == "New!" or ret == "Fuzz":
        print("  ok:", ret)
    else:
        print("  nok:", ret)
        return
    ret = hfuzz_socket.recv()
    if ret == "Fuzz":
        print("  ok:", ret)
    else:
        print("  nok:", ret)
        return

    print()
    print("Test: 2 - expecting second new BB")
    target_socket.sendfuzz(2)
    sendresp(ret, hfuzz_socket)
    ret = hfuzz_socket.recv()
    if ret == "New!":
        print("  ok:", ret)
    else:
        print("  nok:", ret)
        return
    ret = hfuzz_socket.recv()
    if ret == "Fuzz":
        print("  ok:", ret)
    else:
        print("  nok:", ret)
        return

    print()
    print("Test: 3 - repeat second msg, expecting no new BB")
    target_socket.sendfuzz(2)
    sendresp(ret, hfuzz_socket)
    ret = hfuzz_socket.recv()
    if ret == "Fuzz":
        print("  ok:", ret)
    else:
        print("  nok:", ret)
        return

    print()
    print("Test: 4 - crash stack, expect new BB, then crash notification")
    target_socket.sendfuzz(6)
    sendresp(ret, hfuzz_socket)
    # first, a new BB is detected
    ret = hfuzz_socket.recv()
    if ret == "New!":
        print("  ok:", ret)
    else:
        print("  nok:", ret)
        return
    # this leads to a crash
    ret = hfuzz_socket.recv()
    if ret == "Cras":
        print("  ok:", ret)
    else:
        print("  nok:", ret)
        return
    # after the crash, the target should have been restarted, and
    # we are ready to fuzz again
    ret = hfuzz_socket.recv()
    if ret == "Fuzz":
        print("  ok:", ret)
    else:
        print("  nok:", ret)
        return

    print()
    print("Test: 5 - resend second, expecting no new BB")
    target_socket.sendfuzz(2)
    sendresp(ret, hfuzz_socket)
    ret = hfuzz_socket.recv()
    if ret == "Fuzz":
        print("  ok:", ret)
    else:
        print("  nok:", ret)
        return

    print()
    print("Test: 6 - send three, expecting new BB")
    target_socket.sendfuzz(3)
    sendresp(ret, hfuzz_socket)
    ret = hfuzz_socket.recv()
    if ret == "New!":
        print("  ok:", ret)
    elif ret == "Fuzz":
        print("  okish: Should have been New!, but lets continue anyway")
    else:
        print("  nok:", ret)
        return

    if ret == "New!":
        ret = hfuzz_socket.recv()
        if ret == "Fuzz":
            print("  ok:", ret)
        else:
            print("  nok:", ret)
            return

    print()
    print("Test: 7 - send four, new BB")
    target_socket.sendfuzz(4)
    sendresp(ret, hfuzz_socket)
    ret = hfuzz_socket.recv()
    if ret == "New!":
        print("  ok:", ret)
    else:
        print("  nok:", ret)
        return
    ret = hfuzz_socket.recv()
    if ret == "Fuzz":
        print("  ok:", ret)
    else:
        print("  nok:", ret)
        return

    # lets simulate that the server has become unresponsive for some reason.
    # as described in #253
    print()
    print("Test: 8 - fake unresponsive server")
    hfuzz_socket.send("bad!")
    ret = hfuzz_socket.recv()
    if ret == "Fuzz":
        print("  ok:", ret)
    else:
        print("  nok:", ret)
        return

    print()
    print("Test: 9 - send four again, no new BB")
    target_socket.sendfuzz(4)
    sendresp(ret, hfuzz_socket)
    ret = hfuzz_socket.recv()
    if ret == "Fuzz":
        print("  ok:", ret)
    else:
        print("  nok:", ret)
        return

    # shut honggfuzz down
    hfuzz_socket.send("halt")

    # this does not really work yet in honggfuzz.
    if (False):
        # lets make the server unresponsive
        print()
        print("Test: 10 - real unresponsive server")
        target_socket.sendFuzz(8)
        sendresp(ret, hfuzz_socket)
        # we first have a new BB
        ret = hfuzz_socket.recv()
        if ret == "New!":
            print("  ok:", ret)
        else:
            print("  nok:", ret)
            return
        
        print()
        print("Test: 11 - send four again, no new BB")
        target_socket.sendFuzz(4)
        sendresp(ret, hfuzz_socket)
        ret = hfuzz_socket.recv()
        if ret == "Fuzz":
            print("  ok:", ret)
        else:
            print("  nok:", ret)
            return


def interactive(pid):
    hfuzz_socket = HonggfuzzSocket(pid)
    target_socket = TargetSocket()

    hfuzz_socket.connect()

    while(True):
        try:
            recv = hfuzz_socket.recv()

            if recv == "Fuzz":
                # Send the bad data to the target
                i = input("--[ Send Msg #: ")
                print("Send to target: " + str(i))
                if not target_socket.sendfuzz(i):
                    print("Server down. Send: bad!")
                    hfuzz_socket.send("bad!")
                else:
                    hfuzz_socket.send("okay")

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
        print("honggfuzz_socketclient.py [auto/interactive] <pid>")

    if mode == "auto":
        auto(pid)
    elif mode == "interactive":
        interactive(pid)

if __name__ == '__main__':
    main()
