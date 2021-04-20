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
TIMEOUT = 0.2
DEFAULT_RESPONSE_LEN = 30
WINDOW_SIZE = 10

# NetDerper
TARGET_IP = "127.0.0.1"
LOCAL_IP = "127.0.0.1"

TARGET_PORT = 4024
LOCAL_PORT = 4025

# Normal
# TARGET_IP = "192.168.30.14"
# LOCAL_IP = "192.168.30.20"
#
# TARGET_PORT = 4023
# LOCAL_PORT = 7110

SOCK = socket(family=AF_INET, type=SOCK_DGRAM)
SOCK.bind((LOCAL_IP, LOCAL_PORT))
SOCK.settimeout(TIMEOUT)


def check_answer(num, crc, acknowledgement, packet_counter):
    """
    Compares the received data with GOOD.
    """
    if int(crc) == crc32(str(num).encode()):
        if len(acknowledgement) == len(GOOD):
            print("Received GOOD for packet " + str(num) + ".")
            return num, GOOD

        print("Received BAD for packet " + str(num))
        return num, BAD

    print("Received corrupted packet number (crc32 wrong) " + str(int(num)) + ".")
    return packet_counter, BAD


def get_separator_index(answer):
    """
    Returns the indexes of separators in a confirmation packet.
    """
    iterator = 0
    separators = []
    for char in str(answer):
        if char == SEPARATOR:
            separators.append(iterator-2)
        iterator += 1

    return separators


def get_answer(packet_counter):
    """
    Gets and decodes the acknowledgement packet from server.
    """
    # Waits for a response
    try:
        answer = SOCK.recv(DEFAULT_RESPONSE_LEN)
    except timeout:
        print("Confirmation timeout.")
        return packet_counter, BAD

    # Tries to decode data to get the acknowledgement
    try:
        separator_idx = get_separator_index(answer)
        num = int(answer[:separator_idx[0]])
        crc = answer[separator_idx[0] + 1:separator_idx[1]]
        ack = answer[separator_idx[1] + 1:]

        return check_answer(num, crc, ack, packet_counter)
    except Exception as e:
        print("Received corrupted data (" + str(answer) + ").")
        return packet_counter, BAD


def build_packet(packet_counter, data):
    """
    Builds a packet with this structure: packet_number SEPARATOR crc32 SEPARATOR data
    """
    return (str(packet_counter) + SEPARATOR + str(crc32(str(packet_counter).encode() + data)) + SEPARATOR).encode() + data


def send_bytes(buffer):
    """
    Sends the data with packet number and divider to TARGET_IP and TARGET_PORT.
    """
    answers = {}

    print("Sending " + str(len(buffer)) + " packets:")
    for packet_num in buffer.keys():
        print("Sending data (packet number:", str(packet_num) + ") of size", str(len(buffer[packet_num])) + ".")
        SOCK.sendto(build_packet(packet_num, buffer[packet_num]), (TARGET_IP, TARGET_PORT))

    while GOOD not in answers.values():
        for packet_num in buffer.keys():
            answer = (get_answer(packet_num))
            answers[answer[0]] = answer[1]

    for packet_num in answers.keys():
        if answers[packet_num] == GOOD and packet_num in buffer.keys():
            buffer.pop(packet_num)

    print("------------------------------------------------")


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


def send_file(file_name, buffer_length):
    """
    Opens and sends a file with given buffer length.
    """
    packet_counter = 1
    buffer_window = {}
    hash_code = md5()

    with open(file_name, "rb") as f:

        # Adds filename packet to the buffer
        print("Sending file " + file_name + " to address " + TARGET_IP + ":" + str(TARGET_PORT))
        buffer_window[packet_counter] = file_name[4:].encode()
        packet_counter += 1

        # Adds number of packets to the buffer
        n_packets = calculate_amount_of_packets(file_name, buffer_length)
        print("Total packets to send " + str(n_packets) + ".")
        buffer_window[packet_counter] = str(n_packets).encode()
        packet_counter += 1

        buffer = f.read(buffer_length - len(str(packet_counter)))

        while len(buffer_window) != 0:
            if len(buffer_window) >= WINDOW_SIZE or buffer == b"":
                send_bytes(buffer_window)
                if len(buffer_window) == WINDOW_SIZE:
                    continue

            if buffer != b"":
                hash_code.update(buffer)
                buffer_window[packet_counter] = buffer

            packet_counter += 1
            buffer = f.read(buffer_length - len(str(packet_counter)))

            if packet_counter == n_packets:
                print("\nAdding Hash: " + str(hash_code.hexdigest()))
                buffer_window[packet_counter] = str(hash_code.hexdigest()).encode()

        print("\nFile has been sent!")


if __name__ == "__main__":
    file = "inp/small.bmp"
    # file = "inp/sample_640×426.bmp"
    # file = "inp/test1.bmp"
    # file = "inp/udp-packet.png"
    # file = "inp/test2.txt"
    # file = "inp/BIG.bmp"

    start = time()
    send_file(file, BUFFER_LEN)
    end = time()

    print(end - start)
