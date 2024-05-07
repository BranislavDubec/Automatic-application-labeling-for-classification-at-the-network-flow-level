#!/usr/bin/env -S python3 -u


import sys
import json
import struct
import os
pipe_path = "/tmp/firefox_url_pipe"

def getMessage():
    rawLength = sys.stdin.buffer.read(4)
    if len(rawLength) == 0:
        sys.exit(0)
    messageLength = struct.unpack('@I', rawLength)[0]
    message = sys.stdin.buffer.read(messageLength).decode('utf-8')
    return json.loads(message)



old_umask = os.umask(0)

if not os.path.exists(pipe_path):
    os.mkfifo(pipe_path, 0o666)

os.umask(old_umask)

while True:

    with open(pipe_path, "w") as pipe:
        receivedMessage = getMessage()
        pipe.write(f"{json.dumps(receivedMessage)}\n")

