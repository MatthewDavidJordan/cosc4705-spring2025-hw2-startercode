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

            # for loop through the sockets in read
            for sock in read:
                if sock is serverSock:
                    client_sock, client_addr = serverSock.accept()
                    sockets.append(client_sock)
                    clientList.append(client_sock)
                else:
                    try:
                        # Receive message length
                        packed_len = sock.recv(4, socket.MSG_WAITALL)

                        unpacked_size = struct.unpack("!L", packed_len)[0]

                        # Receive actual JSON message
                        message_data = sock.recv(unpacked_size, socket.MSG_WAITALL)

                        # Deserialize and log message
                        msg = UnencryptedIMMessage.deserialize(packed_len, message_data)
                        log.info(f"Received: {msg}")

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
        # if the socket is the server socket, accept the socket and append it to the client list and to that socket's list

        # else check if the length is empty, if it is, remove the socket from the client list and from that socket's list

        # if not process the message and send it to the other clients

        # receiving the message, parsing the json, and sending it to the other clients


if __name__ == "__main__":
    exit(main())
