from socket import *
from multiprocessing import Manager, Process, freeze_support
from os import stat
from zlib import crc32
import hashlib

MIN_NUM_PACKETS = 3     # + filename | + number of packets | + hashcode

TARGET_IP = "192.168.30.38"
LOCAL_IP = "192.168.30.38"

TARGET_PORT = 4023
LOCAL_PORT = 7110
BUFFER_LEN = 1012
TIMEOUT = 1
SEPARATOR = '|'

SOCK = socket(family=AF_INET, type=SOCK_DGRAM)
SOCK.bind((LOCAL_IP, LOCAL_PORT))
SOCK.settimeout(TIMEOUT)


def wait_for_answer():
    """
    Waits for servers confirmation that the data have been received correctly.
    """
    try:
        answer = SOCK.recvfrom(1)
    except timeout:
        answer = 0

    if answer == 0:
        print("Confirmation timeout.\n")
        return answer
    else:
        print("Received " + str(int(answer[0])) + " from address " + str(answer[1]) + ".\n")
        return int(answer[0])


def build_packet(data, packet_counter):
    """
    Builds a packet with this structure: packet_number SEPARATOR crc32 SEPARATOR data
    """
    return (str(packet_counter) + SEPARATOR + str(crc32(data)) + SEPARATOR).encode() + data


def send_bytes(buffer, packet_counter, ):
    """
    Sends the data with packet number and divider to TARGET_IP and TARGET_PORT.
    """
    packet = build_packet(buffer, packet_counter)
    answer = 0

    while answer != 1:  # Tests for successfully received packet
        print("Sending packet " + str(int(packet_counter)) + " of size " + str(len(packet)) + ".")
        SOCK.sendto(packet, (TARGET_IP, TARGET_PORT))
        answer = wait_for_answer()


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
    print("Total packets to send " + str(n_packets) + ".\n")

    send_bytes(file_name.encode(), packet_counter)  # Converts (encodes) the filename to binary
    send_bytes(str(n_packets).encode(), packet_counter + 1)  # Converts the n_packets to binary


def send_file(file_name, buffer_length):
    """
    Opens and sends a file with given buffer length.
    """
    packet_counter = 1
    hash_code = hashlib.md5()

    with open(file_name, "rb") as f:
        print("Sending file " + file_name + " to address " + TARGET_IP + ":" + str(TARGET_PORT))

        send_file_info(file_name, packet_counter, buffer_length)  # Sends information about file
        packet_counter += 2  # +2 for the filename and file size
        buffer = f.read(buffer_length - len(str(packet_counter)))  # Starts reading the file

        while buffer != b"":
            hash_code.update(buffer)
            send_bytes(buffer, packet_counter)
            packet_counter += 1
            buffer = f.read(buffer_length - len(str(packet_counter)))

        send_bytes(str(hash_code.hexdigest()).encode(), packet_counter)
        print(hash_code.hexdigest())


if __name__ == "__main__":
    # file = "sample_640×426.bmp"
    file = "inp/BIG.bmp"

    send_file(file, BUFFER_LEN)
