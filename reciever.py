from hashlib import md5
from socket import socket, AF_INET, SOCK_DGRAM, SOL_SOCKET, SO_REUSEADDR, timeout
from zlib import crc32

localIP = "192.168.30.31"
targetIP = "192.168.30.10"
log = open("log.txt", "w")
localPort = 4023
targetPort = 7110

bufferSize = 1024
CHARACTER = 124
WINDOW_SIZE = 10
DATA_DICT_SIZE = 32
TIMEOUT = 10
LITTLE_TIMEOUT = 3
data_dict = {}  # Contains all data received from sender
confirm_arr = {}  # Contains all ARC
log_dict = []
history_dict = []


def get_hash_code(data):
    return data.decode()


def while_loop_for_data_parse(data, index, number):
    """Simple while loop to get crucial info like a package number or crc32"""
    while data[index] != CHARACTER:
        number += chr(data[index])
        index += 1

    return data, index, number


def increase_index(index):
    index += 1
    return index


class Server:
    """
    UDP server for Computer Networks' class.
    author: Nurkozhin Arlan
    """

    def __init__(self, ip_address, port, buffer_size):
        self.ip_address = ip_address
        self.port = port
        self.buffer_size = buffer_size
        self.filename = ''
        self.udp_server_socket = socket(family=AF_INET, type=SOCK_DGRAM)
        self.count = 1
        self.all_data = b''
        self.amount_of_packages = 0
        self.counter_from_sender = 0  # Counter from sender is number of package
        self.crc32_from_sender = 0
        self.hash_code = md5()
        self.isEnd = False
        self.f = None
        self.is_closed = False
        self.num_before = 1

    def bind_server(self):
        """
        Binds server with sender via sockets
        """
        self.udp_server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self.udp_server_socket.bind((self.ip_address, self.port))
        print("Server runs and listens!")

    def listener(self):
        """
        Main function listens to data from sender. It also writes the file
        """

        while not self.isEnd:
            data = self.get_data_and_addr_from_sender()
            data = self.parse_data(data)
            print(self.count)
            print("Sender's count: " + str(self.counter_from_sender) +
                  " Sender's amount_of_packages: " + str(self.amount_of_packages))

            self.concatenate_data_and_update_hash(data)

            if len(confirm_arr) == 10:
                self.send_confirmations()
                confirm_arr.clear()
                print("Confirm array was cleaned")
            elif self.counter_from_sender == self.amount_of_packages:
                self.send_confirmations()

            if self.counter_from_sender == self.amount_of_packages:
                if len(data_dict) % DATA_DICT_SIZE == 0:
                    self.close_file()
                    self.is_closed = True
                else:
                    self.write_file()
                    self.close_file()
                    self.is_closed = True

            self.compare_hash_codes(data)

        print(self.filename + " was created!")

    def get_filename(self, data):
        """
        Decode filename from byte data
        """
        try:
            self.filename = data.decode("utf-8")
            print("Filename got success: " + self.filename)
        except Exception as e:
            print("Error with filename decoding! ", e)

    def get_size(self, data):
        """
        Decode file's size from byte data
        """
        try:
            self.amount_of_packages = int(data.decode("utf-8"))
            print("Size got success: " + str(self.amount_of_packages))
        except Exception as e:
            print("Invalid data for get_size function.", e)

    def make_file(self):
        with open("out/" + self.filename, "wb") as f:
            f.write(self.all_data)
        print("File was created!")

    def close_socket(self):
        self.udp_server_socket.close()

    def send_bytes(self, data):
        self.udp_server_socket.sendto(data, (targetIP, targetPort))

    def send_error(self):
        msg = str(self.counter_from_sender) + "|" + str(crc32(str(self.counter_from_sender).encode())) + "|" + "BAD"
        confirm_arr[self.counter_from_sender] = msg.encode()
        # self.send_bytes(msg.encode())
        print("BAD was added to array\n")

    def send_success(self):
        msg = str(self.counter_from_sender) + "|" + str(crc32(str(self.counter_from_sender).encode())) + "|" + "GOOD"
        confirm_arr[self.counter_from_sender] = msg.encode()
        # self.send_bytes(msg.encode())
        print("GOOD was added to array\n")

    def parse_data(self, data):
        """Reads input data up to char '|' then return data without chars before the char '|' """
        try:
            data = self.get_package_counter_from_sender(data)
            return self.get_crc32_from_sender(data)
        except Exception as e:
            print("Error with parsing data ", e)
            return None

    def control_crc(self, data):
        """Control crc32 received from sender with my crc32"""
        try:
            if int(self.crc32_from_sender) == crc32(str(self.counter_from_sender).encode() + data):
                print("Crc is fine")

            return int(self.crc32_from_sender) == crc32(str(self.counter_from_sender).encode() + data)
        except Exception as e:
            print("Error with crc!", e)

            return False

    def get_package_counter_from_sender(self, data):
        """Gets package counter from sender"""
        index = 0
        num = ""

        data, index, num = while_loop_for_data_parse(data, index, num)
        self.counter_from_sender = int(num)

        index = increase_index(index)

        return data[index:]

    def get_crc32_from_sender(self, data):
        """Gets crc32 from sender"""
        index = 0
        crc = ""

        data, index, crc = while_loop_for_data_parse(data, index, crc)

        self.crc32_from_sender = int(crc)
        index = increase_index(index)

        return data[index:]

    def compare_hash_codes(self, data):
        """Compares sender's sent hash vs my generated hash"""
        print("self.counter from sender == self.amount_of_packages")

        print(self.counter_from_sender, self.amount_of_packages)
        if self.counter_from_sender == self.amount_of_packages and self.control_crc(data):
            hash_from_sender = get_hash_code(data)

            print("Hash from sender: " + hash_from_sender)
            print("My hash:          " + str(self.hash_code.hexdigest()))
            if hash_from_sender == self.hash_code.hexdigest():
                print("Hash codes are equal!")

                self.send_success()
            else:
                self.send_error()

    def check_package_and_crc(self, data):
        """It checks if servers' counter equals to counter from sender"""
        if self.control_crc(data):  # self.check_packages() == 1 and
            return True
        else:
            if self.counter_from_sender < self.count:
                return True

            return False

    def get_data_and_addr_from_sender(self):
        """
        It receives tuple (data, address) from sender. Where data is a package.
        """
        if self.counter_from_sender == self.amount_of_packages:
            try:
                data, addr = self.udp_server_socket.recvfrom(self.buffer_size)
                self.udp_server_socket.settimeout(TIMEOUT)  # Remove timeout
                print("----------------------------------------------------------")
                print('received from: ', addr, 'data: package_' + str(self.count))
                print(data)
                return data
            except timeout:
                print("Sender received success confirmation. Listener function ended\n")

                self.isEnd = True
        else:
            # try:
            data, addr = self.udp_server_socket.recvfrom(self.buffer_size)
            # self.udp_server_socket.settimeout(LITTLE_TIMEOUT)  # Remove timeout
            print("----------------------------------------------------------")
            print('received from: ', addr, 'data: package_' + str(self.counter_from_sender))
            print()
            return data
            # except timeout:
            #     print("Confirm array: " + str(len(confirm_arr)))

    def concatenate_data_and_update_hash(self, data):
        """
        It concatenates data from sender and writes it in file
        """
        if self.control_crc(data):  # self.count < self.amount_of_packages
            if self.counter_from_sender < self.count and self.control_crc(data):
                print(str(self.counter_from_sender) + " Was inserted")
                data_dict[self.counter_from_sender] = data
                self.send_success()
            else:
                print("Packet was received")

                if len(data_dict) == DATA_DICT_SIZE:
                    # write file
                    self.write_file()
                    data_dict.clear()
                    print("All data array was cleaned")

                # self.hash_code.update(data)
                # (str(self.counter_from_sender).encode() + '|'.encode() + data)]
                print("Counter from sender before data_dict: " + str(self.counter_from_sender))
                data_dict[self.counter_from_sender] = data
                print("Data was appended")
                print(data)
                print("All data array: " + str(len(data_dict)))

                self.send_success()
                self.count += 1
        else:
            self.send_error()

    def write_file(self):
        # Tests var:
        print("BEFORE DATA WRITE LOOP:")

        print(data_dict.keys())
        # sorted_data_dict = {k: data_dict[k] for k in sorted(data_dict, key=data_dict.get)}
        print(sorted(data_dict))
        for package_number in sorted(data_dict):
            data = data_dict[package_number]
            print("Got package number " + str(package_number))
            if self.num_before < package_number:
                log_dict.append(self.num_before)
            if package_number == 1:
                self.get_filename(data)
                self.f = open("out/" + self.filename, "wb")
            elif package_number == 2:
                self.get_size(data)
            else:
                if package_number != self.amount_of_packages and not self.is_closed:

                    if len(history_dict) == 40:
                        history_dict.clear()

                    if package_number not in history_dict:
                        print("Written data: ", end='')
                        print(data)
                        self.f.write(data)
                        self.hash_code.update(data)
                        history_dict.append(package_number)
                    else:
                        print(str(package_number) + " Was prevented")

            self.num_before += 1

    def send_confirmations(self):
        """
        Send data confirmations in a row of WINDOW_SIZE
        """
        # sorted_confirm_arr = {k: confirm_arr[k] for k in sorted(confirm_arr, key=confirm_arr.get)}

        for conf in sorted(confirm_arr):
            print(confirm_arr[conf])
            self.send_bytes(confirm_arr[conf])

    def close_file(self):
        self.f.close()


# Start
# Creating server. If everything is OK, receive a filename, size and all data
my_server = Server(localIP, localPort, bufferSize)
my_server.bind_server()

my_server.listener()
# my_server.make_file()
my_server.close_socket()
log.close()
print(log_dict)
