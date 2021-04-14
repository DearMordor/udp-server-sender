from socket import socket, AF_INET, SOCK_DGRAM, timeout
from os import stat
from zlib import crc32
from hashlib import md5
from time import time

MIN_NUM_PACKETS = 3  # + filename | + number of packets | + hashcode
BAD = b"BAD"
GOOD = b"GOOD"
SEPARATOR = '|'
BUFFER_LEN = 1012   # The length of the packet varies from 1023 to 1024
TIMEOUT = 0.3
DEFAULT_RESPONSE_LEN = 30
WINDOW_SIZE = 100

# NetDerper
# TARGET_IP = "127.0.0.1"
# LOCAL_IP = "127.0.0.1"
#
# TARGET_PORT = 4024
# LOCAL_PORT = 4025

# Normal
TARGET_IP = "192.168.30.20"
LOCAL_IP = "192.168.30.20"

TARGET_PORT = 4023
LOCAL_PORT = 7110

SOCK = socket(family=AF_INET, type=SOCK_DGRAM)
SOCK.bind((LOCAL_IP, LOCAL_PORT))
SOCK.settimeout(TIMEOUT)


def check_answer(num, acknowledgement, packet_counter):
    """
    Compares the received data with GOOD.
    """
    if num != packet_counter:
        print(''.join(["Received old confirmation for packet ", str(num), ", waiting for another."]))
        return get_answer(packet_counter)
    if len(acknowledgement) == len(GOOD):
        print("Received GOOD for " + str(num) + ".")
        return GOOD

    print(''.join(["Received corrupted data or BAD (", str(acknowledgement), "), sending packet again."]))
    return BAD


def get_answer(packet_counter):
    """
    Gets and decodes the acknowledgement packet from server.
    """
    # Waits for a response
    try:
        answer = SOCK.recv(DEFAULT_RESPONSE_LEN)
    except timeout:
        print("Confirmation timeout, sending packet again.")
        return BAD

    # Tries to decode data to get the acknowledgement
    try:
        separator_idx = len(str(packet_counter))
        num = int(answer[:separator_idx])
        ack = answer[separator_idx + 1:]

        return check_answer(num, ack, packet_counter)
    except Exception as e:
        print("Received corrupted data, sending packet again.", e)
        return BAD


def build_packet(data, packet_counter):
    """
    Builds a packet with this structure: packet_number SEPARATOR crc32 SEPARATOR data
    """
    return (str(packet_counter) + SEPARATOR + str(crc32(data)) + SEPARATOR).encode() + data


def send_bytes(buffer, packet_counter):
    """
    Sends the data with packet number and divider to TARGET_IP and TARGET_PORT.
    """
    recv_bad_buffer = []

    print("Sending " + str(len(buffer)) + " packets:")
    for i in range(len(buffer)):
        print(''.join(["Sending data (packet number: ", str(int(packet_counter - len(buffer) + i + 1)), ") of size ", str(len(buffer[i])), "."]))
        SOCK.sendto(build_packet(buffer[i], packet_counter - len(buffer) + i + 1), (TARGET_IP, TARGET_PORT))
        if get_answer(packet_counter - len(buffer) + i + 1) == BAD:
            recv_bad_buffer.append(buffer[i])

    print()
    return recv_bad_buffer


def calculate_amount_of_packets(filename, buffer_length):
    """
    Calculates how many packets will be sent with given buffer length and filename.
    """
    number = MIN_NUM_PACKETS
    file_size = stat(filename).st_size
    while file_size > 0:
        file_size -= buffer_length - len(str(number))
        number += 1

    return number


def send_file_info(file_name, packet_counter, buffer_lenght):
    """
    Sends the necessary file information.
    -> file name
    -> number of packets (with predetermined buffer length 1012)
    """
    n_packets = calculate_amount_of_packets(file_name, buffer_lenght)
    print("Total packets to send " + str(n_packets) + ".")

    send_bytes([file_name[4:].encode()], packet_counter)  # Converts (encodes) the filename to binary
    send_bytes([str(n_packets).encode()], packet_counter + 1)  # Converts the n_packets to binary


def send_file(file_name, buffer_length):
    """
    Opens and sends a file with given buffer length.
    """
    packet_counter = 1
    buffer_window = []
    hash_code = md5()

    with open(file_name, "rb") as f:
        print("Sending file " + file_name + " to address " + TARGET_IP + ":" + str(TARGET_PORT))

        send_file_info(file_name, packet_counter, buffer_length)  # Sends information about file
        packet_counter += 2  # +2 for the filename and file size
        buffer = f.read(buffer_length - len(str(packet_counter)))

        while buffer != b"":
            hash_code.update(buffer)
            buffer_window.append(buffer)

            if len(buffer_window) == WINDOW_SIZE:
                buffer_window = send_bytes(buffer_window, packet_counter)

            packet_counter += 1
            buffer = f.read(buffer_length - len(str(packet_counter)))
        if len(buffer_window) > 0:
            send_bytes(buffer_window, packet_counter - 1)
        print("\nSending Hash: " + str(hash_code.hexdigest()))
        send_bytes([str(hash_code.hexdigest()).encode()], packet_counter)
        print("\nFile has been sent!")


if __name__ == "__main__":
    # file = "inp/small.bmp"
    # file = "inp/sample_640×426.bmp"
    file = "inp/test1.bmp"
    # file = "inp/udp-packet.png"
    # file = "inp/test2.txt"
    # file = "inp/BIG.bmp"

    start = time()
    send_file(file, BUFFER_LEN)
    end = time()

    print(end - start)
