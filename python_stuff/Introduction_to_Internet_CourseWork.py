#!/usr/bin/python
# -*- coding: utf-8 -*-
import secrets
import struct

# The modules required
import sys
import socket

'''
This is a template that can be used in order to get started. 
It takes 3 commandline arguments and calls function send_and_receive_tcp.
in haapa7 you can execute this file with the command: 
python3 CourseWorkTemplate.py <ip> <port> <message> 

Functions send_and_receive_tcp contains some comments.
If you implement what the comments ask for you should be able to create 
a functioning TCP part of the course work with little hassle.  

'''

'''
server_address = "195.148.20.105"
server_tcp_port = 10000
'''
parity_enabled = False  # TODO: add a global variable for encryption and multipart messaging?

def send_and_receive_tcp(address, port, msg):
    print("You gave arguments: {} {} {}".format(address, port, msg))

    '''
    Each message must end in carriage return and newline (\r\n)
    
    message structure: "HELLO ENC* MUL* PAR*\r\n"   *optional
    '''
    msg = msg + "\r\n"

    if "PAR" in msg:
        global parity_enabled
        parity_enabled = True

    # generate keys and add them to the initial message
    my_keys = []
    if "ENC" in msg:
        my_keys = generate_keys(20)
        for i in range(len(my_keys)):
            msg = msg + my_keys[i] + "\r\n"
        msg = msg + ".\r\n"

    # create TCP socket
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # connect socket to given address and port
    tcp_socket.connect((address, port))
    # python3 sendall() requires bytes like object. encode the message with str.encode() command
    encoded_message = msg.encode()
    # send given message to socket
    tcp_socket.sendall(encoded_message)
    # receive data from socket
    received_bytes = tcp_socket.recv(2048)
    # data you received is in bytes format. turn it to string with .decode() command
    received_data = received_bytes.decode()
    # print received data
    print("received data: " + received_data)

    # separate encryption keys from other data
    received_msg = []
    received_msg = received_data.split("\r\n")
    their_keys = received_msg[1:-2]

    # Get your CID and UDP port from the message
    hello, cid, udp_port = received_msg[0].split(" ")
    udp_port = int(udp_port)

    # close the socket
    tcp_socket.close()

    # Continue to UDP messaging. You might want to give the function some other parameters like
    # the above mentioned cid and port.
    send_and_receive_udp(address, udp_port, cid, my_keys, their_keys)
    return


def generate_keys(count):
    keys = []
    for i in range(count):
        # each byte gets converted two hexadecimal digits, 32 bytes -> 64 hexadecimal digits
        keys.append(secrets.token_hex(32))

    return keys


def send_and_receive_udp(address, port, cid, my_keys, their_keys):
    """
    @param address: server address
    @param port: server port
    @param cid: CID given by the server
    @param my_keys: [<key1>, <key2>...]
    @param their_keys: [<key1>, <key2>...]
    @return:
    """
    '''
    UDP packet structure

        CID         ACK     EOM     Data remaining      Content length    Content
        Char[8]     Bool    Bool    Unsigned short      Unsigned short    Char[128]

        CID: 8 byte string containing the client's identification token received from the server's hello
        message. May be ignored when receiving from the server.

        ACK: Boolean value whether the last message received correctly or not. Used with the parity
        check feature, otherwise always True.

        EOM: Set as True in the last message the server will send, otherwise always False

        Data remaining: Length of the data remaining when using multipart messages. If multipart
        messages are not supported, value is always 0.

        Content length: Length of the message (without padding) in the content field before
        encoding. Use this value to extract the exact message from the content field.

        Content: 128 byte string of message content. If the content is smaller than 128 bytes it will
        be padded with null bytes. Content length should be used to get only the message. In
        implementations where there is no parity server sends messages that are at most 64 bytes
        long and expects messages that are the same size. If you are implementing multipart
        messages send your data in chunks of 64

        Byte order is network byte order (big-endian)
    '''

    # create the udp socket
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.connect((address, port))

    # initial message
    msg = "Hello from " + cid

    # loop for communicating with the server
    # TODO: timeout in case no eom
    eom = False
    parity_correct = True
    my_key_number = 0  # key number
    their_key_number = 0
    while not eom:
        print(f"\nmessage length is {len(msg)}")

        # split message to pieces for multipart messaging
        msg_pieces = split_message_to_pieces(msg)
        data_remaining = len(msg)
        # create and send packets
        for i, msg_piece in enumerate(msg_pieces):

            # msg length before adding parity bits
            data_remaining -= len(msg_piece)


            # encrypt message
            encrypted_msg = encrypt_message(msg_piece, my_keys, my_key_number)
            my_key_number += 1

            # add parity bits to the message before encryption
            if parity_enabled:
                encrypted_msg = add_parity_to_message(encrypted_msg)

            packet = pack_data(cid, encrypted_msg, ack=parity_correct, data_remaining=data_remaining)

            udp_socket.sendall(packet)

            print(f"Sent message piece {i+1} out of {len(msg_pieces)}")

        # receive data
        data_remaining = 1
        all_content = ""
        parity_correct = True
        while data_remaining > 0:
            data = udp_socket.recv(1024)
            print("received data")
            new_cid, ack, eom, data_remaining, content_length, content = struct.unpack("!8s??HH128s", data)

            content = content.decode()[:content_length]

            # remove parity, last message does not have parity
            if parity_enabled and not eom:
                parity_correct = parity_correct and check_parity(content)  # if false stays false for multipart msg
                print("Parity correct: ", parity_correct)
                content = remove_parity_from_message(content)

            # add new message content to all_content
            if not eom:
                all_content += decrypt_message(content, their_keys, their_key_number)
                their_key_number += 1

            # last message is not encrypted
            if eom:
                all_content += content
                print(content)

        print("Received message from server: ", all_content)

        # create the reply message, reverses the order of words
        if parity_correct:
            msg = " ".join(all_content.split(" ")[::-1])
        elif not parity_correct:
            msg = "Send again"

    # close socket
    udp_socket.close()

    return


def get_parity(n):
    """
    calculates even parity for n
    """
    n = ord(n)
    while n > 1:
        n = (n >> 1) ^ (n & 1)
    return n


def add_parity(n):
    """
    @param n:
    @return: n + parity bit
    """
    n = ord(n)
    # print("adding parity bit\n1", bin(n))
    n <<= 1
    # print("2", bin(n))
    n += get_parity(chr(n))
    # print("3", bin(n))
    return chr(n)


def remove_parity_bit(n):
    n = ord(n)
    #print("removing parity bit\n1", bin(n))
    n >>= 1
    #print("2", bin(n))
    return chr(n)


def remove_parity_from_message(msg: str):
    text = ""
    for c in msg:
        text += remove_parity_bit(c)
    return text


def check_parity(msg: str):
    """
    @param msg:
    @return: True, if parity is correct, otherwise False
    """
    parity_bit = msg[-1]
    for c in msg:
        c = remove_parity_bit(c)
        if parity_bit == get_parity(c):
            return False
    return True


def add_parity_to_message(msg: str):
    text = ""
    for c in msg:
        text += add_parity(c)
    return text

def split_message_to_pieces(msg: str, piece_length=64):
    """
    Splits the message to pieces for multipart messaging
    @param msg:
    @param piece_length:
    @return: [<piece1>, <piece2>...]
    """
    pieces = []
    for i in range(((len(msg)-1) // piece_length) + 1):
        pieces.append(msg[(i*piece_length):(i*piece_length+piece_length)])

    print(f"The message was split to {i+1} pieces: ")
    print(pieces)
    return pieces


def encrypt_message(msg: str, keys: list[str], key_number: int):
    """
    Encrypts the message with the given key. Returns unencrypted message if out of keys.
    @param msg: message
    @param keys: [<key1>,<key2>...]
    @param key_number: 1,2...
    @return: encrypted message or unencrypted message if out of keys
    """
    # if out of keys
    if key_number >= len(keys):
        print("Out of keys, message was not encrypted")
        return msg

    print("Encrypting/decrypting with key ", key_number)

    encrypted_msg = ""
    for i in range(len(msg)):
        encrypted_msg += chr(ord(msg[i]) ^ ord(keys[key_number][i]))
    return encrypted_msg


def decrypt_message(msg: str, keys: list[str], key_number: int):
    """
    @param msg: encrypted message
    @param keys: [<key1>,<key2>...]
    @param key_number: 1,2...
    @return: decrypted message
    """
    return encrypt_message(msg, keys, key_number)


def pack_data(cid, content, ack=True, eom=False, data_remaining=0):
    if data_remaining < 0:
        data_remaining = 0
    content_length = len(content)
    # print(f"Content length is {content_length}")
    cid = cid.encode()
    # print(f"CID is {cid}")
    content = content.encode()
    # print(f"Content is {content}")
    packet = struct.pack("!8s??HH128s", cid, ack, eom, data_remaining, content_length, content)
    # print(f"Packet is {packet}")
    """
    new_cid, ack, eom, data_remaining, content_length, content = struct.unpack("!8s??HH128s", packet)
    print(f"unpacked")
    print(new_cid, ack, eom, data_remaining, content_length, content)
    """
    return packet


def main():
    USAGE = ('usage: %s <server address> <server port> <message> \n <message> must include HELLO, optional in the'
             'message are ENC (encryption), MUL (multipart messages) and PAR (parity), the program should work'
             'with any combination of ENC MUL and PAR') % sys.argv[0]

    try:
        # Get the server address, port and message from command line arguments
        server_address = str(sys.argv[1])
        server_tcpport = int(sys.argv[2])
        message = str(sys.argv[3])
    except IndexError:
        print("Index Error")
    except ValueError:
        print("Value Error")
    # Print usage instructions and exit if we didn't get proper arguments
        sys.exit(USAGE)

    send_and_receive_tcp(server_address, server_tcpport, message)


if __name__ == '__main__':
    # Call the main function when this script is executed
    main()
