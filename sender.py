from socket import *
from multiprocessing import Manager, Process
from os import stat
from zlib import crc32
import hashlib

MIN_NUM_PACKETS = 2     # + filename | + number of packets | + STOP

TARGET_IP = "192.168.30.25"
LOCAL_IP = "192.168.30.25"

TARGET_PORT = 4023
LOCAL_PORT = 7110
BUFFER_LEN = 1012
TIMEOUT = 0.3
SEPARATOR = '|'

SOCK = socket(family=AF_INET, type=SOCK_DGRAM)


def recv_with_return(return_list, my_socket):
    """
    Special function for returning the output of Process class.
    """
    return_list.append(my_socket.recvfrom(1))


def wait_for_answer(answer):
    """
    Waits for servers confirmation that the data have been received correctly.
    """
    receiving = Process(target=recv_with_return, args=[answer, SOCK])
    receiving.start()
    receiving.join(timeout=TIMEOUT)
    receiving.terminate()

    if len(answer) == 0:
        print("Confirmation timeout.\n")
        return 0
    else:
        print("Received " + str(answer[0][0])[2] + " from address " + str(answer[0][1]) + ".\n")
        return int(answer[0][0])


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
    answer_manager = Manager().list()
    answer = 1
    SOCK.sendto(packet, (TARGET_IP, TARGET_PORT))

    while answer != 1:  # Waits for confirmation
        print("Sending packet " + str(int(packet_counter)) + " of size " + str(len(packet)) + ".")
        #print(chr(bytes_to_send[:15]))
        SOCK.sendto(packet, (TARGET_IP, TARGET_PORT))
        answer = wait_for_answer(answer_manager)


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
    -> number of packets (with predetermined buffer length 1024)
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
    SOCK.bind((LOCAL_IP, LOCAL_PORT))
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
        #send_bytes("STOP".encode(), packet_counter)


if __name__ == "__main__":
    file = "inp/golang.png"
    send_file(file, BUFFER_LEN)

# Test gitlab 2
