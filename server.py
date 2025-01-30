import socket
import json
import argparse
import logging
import select
import struct
import time
import sys

from message import UnencryptedIMMessage


def parseArgs():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--port",
        "-p",
        dest="port",
        type=int,
        default="9999",
        help="port number to listen on",
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
    args = parseArgs()  # parse the command-line arguments

    # set up logging
    log = logging.getLogger("myLogger")
    logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s")
    level = logging.getLevelName(args.loglevel)
    log.setLevel(level)
    log.info(f"running with {args}")

    log.debug("waiting for new clients...")
    serverSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSock.bind(("", args.port))
    serverSock.listen()

    clientList = []

    sockets = [serverSock]

    try:
        while True:

            read, write, errors = select.select(sockets, sockets, sockets)

            for sock in read:
                if sock is serverSock:
                    client_sock, client_addr = serverSock.accept()
                    sockets.append(client_sock)
                    clientList.append(client_sock)
                else:
                    try:
                        packed_len = sock.recv(4, socket.MSG_WAITALL)
                        unpacked_size = struct.unpack("!L", packed_len)[0]

                        message_data = sock.recv(unpacked_size, socket.MSG_WAITALL)
                        msg = UnencryptedIMMessage.deserialize(packed_len, message_data)

                        # Broadcast the message to other clients
                        for client in clientList:
                            if client is not sock:
                                packed_size, json_data = msg.serialize()
                                client.sendall(packed_size)
                                client.sendall(json_data)

                    except (ConnectionResetError, struct.error):
                        log.info("Client disconnected.")
                        sock.close()
                        sockets.remove(sock)
                        clientList.remove(sock)

    except KeyboardInterrupt:
        log.info("\nShutting down server...")
        for client in clientList:
            client.close()
        serverSock.close()
        log.info("Server stopped.")
        sys.exit(0)


if __name__ == "__main__":
    exit(main())
