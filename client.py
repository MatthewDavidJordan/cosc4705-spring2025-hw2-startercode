"""
A skeleton from which you should write your client.
"""

import socket
import json
import argparse
import logging
import select
import sys
import time
import datetime
import struct

from message import UnencryptedIMMessage


def parseArgs():
    """
    parse the command-line arguments
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--port",
        "-p",
        dest="port",
        type=int,
        default="9999",
        help="port number to connect to",
    )
    parser.add_argument(
        "--server", "-s", dest="server", required=True, help="server to connect to"
    )
    parser.add_argument(
        "--nickname", "-n", dest="nickname", required=True, help="nickname"
    )
    parser.add_argument(
        "--loglevel",
        "-l",
        dest="loglevel",
        choices=["DEBUG", "INFO", "WARN", "ERROR", "CRITICAL"],
        default="INFO",
        help="log level",
    )
    args = parser.parse_args()
    return args


def main():
    args = parseArgs()

    # set up the logger
    log = logging.getLogger("myLogger")
    logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s")
    level = logging.getLevelName(args.loglevel)

    log.setLevel(level)
    log.info(f"running with {args}")

    log.debug(f"connecting to server {args.server}")
    try:
        s = socket.create_connection((args.server, args.port))
        log.info("connected to server")
    except:
        log.error("cannot connect")
        exit(1)

    # here's a nice hint for you...
    readSet = [s] + [sys.stdin]
    try:
        while True:
            read, write, errors = select.select(readSet, [s], readSet)

            for sock in read:
                if sock == s:
                    try:
                        # Receive the 4-byte message length
                        packedLen = sock.recv(4, socket.MSG_WAITALL)
                        if not packedLen:
                            log.info("Server closed the connection.")
                            sys.exit(0)

                        # Unpack length
                        unpackedSize = struct.unpack("!L", packedLen)[0]

                        # Receive the actual JSON message
                        message_data = sock.recv(unpackedSize, socket.MSG_WAITALL)
                        if not message_data:
                            log.info("Server closed the connection.")
                            sys.exit(0)

                        # Deserialize the message
                        msg = UnencryptedIMMessage.deserialize(packedLen, message_data)

                        # Print the received message
                        print(msg)

                    except Exception as e:
                        log.error(f"Error receiving message: {e}")
                        sys.exit(1)
                else:
                    # Handle user input
                    message = sys.stdin.readline().strip()
                    if message:
                        msg = UnencryptedIMMessage(args.nickname, message)
                        (packedSize, jsonData) = msg.serialize()

                        # Send the length first
                        s.sendall(packedSize)

                        # Send the actual JSON message
                        s.sendall(jsonData)
    except KeyboardInterrupt:
        log.info("\nKeyboard Interrupt detected. Exiting...")
        s.close()
        sys.exit(0)


if __name__ == "__main__":
    exit(main())
