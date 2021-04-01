from socket import *
from os import stat
from zlib import crc32
from time import sleep
import hashlib

MIN_NUM_PACKETS = 3  # + filename | + number of packets | + hashcode
BAD = b"BAD"
GOOD = b"GOOD"
SEPARATOR = '|'
BUFFER_LEN = 1012
TIMEOUT = 0.3

# NetDerper
TARGET_IP = "192.168.30.38"
LOCAL_IP = "192.168.30.38"

TARGET_PORT = 4024
LOCAL_PORT = 4025

# Normal
# TARGET_IP = "192.168.30.15"
# LOCAL_IP = "192.168.30.38"
#
# TARGET_PORT = 4023
# LOCAL_PORT = 7110


SOCK = socket(family=AF_INET, type=SOCK_DGRAM)
SOCK.bind((LOCAL_IP, LOCAL_PORT))
SOCK.settimeout(TIMEOUT)


def get_separator_index(data):
    """
    Goes through data and returns the index of the SEPARATOR.
    """
    iterator = 0
    for char in data:
        if char == SEPARATOR:
            break
        iterator += 1
    return iterator


def check_answer(num, acknowledgement, packet_counter):
    """
    Compares the received data with GOOD.
    """
    if num != packet_counter:
        print("Received old confirmation for packet " + str(num) + ", waiting for another.")
        return get_answer(packet_counter)
    if len(acknowledgement) == len(GOOD):
        print("Received GOOD, sending next packet.")
        return GOOD

    print("Received corrupted data or BAD (" + str(acknowledgement) + "), sending packet again.")
    return BAD


def get_answer(packet_counter):
    """
    Gets and decodes the acknowledgement packet from server.
    """
    # Waits for a response
    try:
        answer = SOCK.recvfrom(30)
    except timeout:
        print("Confirmation timeout, sending packet again.")
        return BAD

    # Tries to decode data to get the acknowledgement
    try:
        received_data = answer[0].decode()
        separator_idx = get_separator_index(received_data)
        num = int(answer[0][:separator_idx])
        ack = answer[0][separator_idx + 1:]

        return check_answer(num, ack, packet_counter)
    except Exception as e:
        print("Received corrupted data, sending packet again.")
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
    packet = build_packet(buffer, packet_counter)
    answer = BAD

    while answer != GOOD:  # Tests for successfully received packet
        print("\nSending packet " + str(int(packet_counter)) + " of size " + str(len(packet)) + ".")
        SOCK.sendto(packet, (TARGET_IP, TARGET_PORT))
        answer = get_answer(packet_counter)


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

    send_bytes(file_name.encode(), packet_counter)  # Converts (encodes) the filename to binary
    send_bytes(str(n_packets).encode(), packet_counter + 1)  # Converts the n_packets to binary


def send_file(file_name, buffer_length):
    """
    Opens and sends a file with given buffer length.
    """
    packet_counter = 1
    hash_code = hashlib.md5()

    sleep(1)

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
        print("\nFile has been sent!")


if __name__ == "__main__":
    file = "inp/small.bmp"
    # file = "inp/sample_640×426.bmp"
    # file = "inp/test1.bmp"
    # file = "inp/BIG.bmp"

    send_file(file, BUFFER_LEN)
