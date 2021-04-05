from hashlib import md5
from socket import socket, AF_INET, SOCK_DGRAM, SOL_SOCKET, SO_REUSEADDR, timeout
from zlib import crc32

localIP = "192.168.30.38"
targetIP = "192.168.30.38"

localPort = 4023
targetPort = 7110

bufferSize = 1024
CHARACTER = 124
TIMEOUT = 5


def get_hash_code(data):
    return data.decode()


def while_loop_for_data_parse(data, index, number):
    while data[index] != CHARACTER:
        if index > 50:
            break
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
        self.counter_from_sender = 0
        self.crc32 = 0
        self.hash_code = md5()
        self.isEnd = False
        self.f = None

    def bind_server(self):
        """Binds server with sender via sockets"""
        self.udp_server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self.udp_server_socket.bind((self.ip_address, self.port))
        print("Server runs and listens!")

    def check_packages(self):
        """Checks a current count from sender and compares with local count"""
        if self.counter_from_sender == self.count:
            return 1
        else:
            if self.counter_from_sender < self.count:
                return 0

            if self.count < 0:
                self.count = 0

            return 0

    def listener(self):
        """Main function listens to data from sender. It also writes the file"""
        while not self.isEnd:
            data = self.get_data_and_addr_from_sender()
            data = self.parse_data(data)

            if data is None:
                self.send_error()
                continue

            if self.count == 1:  # At first iteration we get the filename. If not, continue ask receiver
                self.get_filename(data)

                if not self.check_packages_and_crc(data):
                    print("Iteration was continued")
                    self.send_success_or_error()
                    continue
                else:
                    self.send_success()
                    self.f = open("out/" + self.filename, "wb")
                    self.count += 1

            elif self.count == 2:  # At second we do the same, but with file's size ( amount of packages)
                self.get_size(data)

                if not self.check_packages_and_crc(data):
                    print("Iteration was continued")
                    self.send_success_or_error()
                    continue
                else:
                    self.send_success()
                    self.count += 1
            else:
                print("Server's count " + str(self.count) + " Sender's amount_of_packages " +
                      str(self.amount_of_packages))
                self.compare_hash_codes(data)
                self.concatenate_data_update_hash(data)

        if self.count % 300 == 0:
            self.f.close()
        else:
            self.f.write(self.all_data)
            self.f.close()

        print(self.filename + " was created!")

    def get_filename(self, data):
        try:
            self.filename = data.decode("utf-8")
            print("Filename got success: " + self.filename)
        except Exception as e:
            print("Error with filename decoding! ", e)

    def get_size(self, data):
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
        msg = str(self.counter_from_sender) + "|" + "BAD"
        self.send_bytes(msg.encode())
        print("Error was sent to the client\n")

    def send_success(self):
        msg = str(self.counter_from_sender) + "|" + "GOOD"
        self.send_bytes(msg.encode())
        print("Success was sent to the client\n")

    def parse_data(self, data):
        """Reads input data up to char '|' then return data without chars before the char '|' """
        try:
            data = self.get_package_counter_from_sender(data)
            return self.get_src_from_sender(data)
        except Exception as e:
            print("Error with parsing data ", e)
            return None

    def control_crc(self, data):
        try:
            return int(self.crc32) == crc32(data)
        except Exception as e:
            print("Error with crc!", e)
            return False

    def get_package_counter_from_sender(self, data):
        index = 0
        num = ""

        data, index, num = while_loop_for_data_parse(data, index, num)
        self.counter_from_sender = int(num)

        index = increase_index(index)

        return data[index:]

    def get_src_from_sender(self, data):
        index = 0
        crc = ""

        data, index, crc = while_loop_for_data_parse(data, index, crc)

        self.crc32 = int(crc)
        index = increase_index(index)

        return data[index:]

    def compare_hash_codes(self, data):
        if self.count == self.amount_of_packages and self.check_packages_and_crc(data):
            hash_from_sender = get_hash_code(data)

            print("Hash from sender: " + hash_from_sender)
            print("My hash:          " + str(self.hash_code.hexdigest()))

            if hash_from_sender == self.hash_code.hexdigest():
                print("Hash codes are equal!")
                self.send_success()
                self.count += 1
            else:
                self.send_error()

    def check_packages_and_crc(self, data):
        """It checks if servers' counter equals to counter from sender"""
        if self.check_packages() == 1 and self.control_crc(data):
            return True
        else:
            if self.counter_from_sender < self.count:
                return False

            return False

    def send_success_or_error(self):
        if self.counter_from_sender < self.count:
            self.send_success()
        else:
            self.send_error()

    def get_data_and_addr_from_sender(self):
        """It receives tuple (data, address) from sender"""
        if self.count >= self.amount_of_packages:
            try:
                data, addr = self.udp_server_socket.recvfrom(self.buffer_size)
                self.udp_server_socket.settimeout(TIMEOUT)
                print('received from: ', addr, 'data: package_' + str(self.count))
                return data
            except timeout:
                print("Sender received success confirmation. Listener function ended\n")
                self.isEnd = True
        else:
            data, addr = self.udp_server_socket.recvfrom(self.buffer_size)

            print('received from: ', addr, 'data: package_' + str(self.count))
            return data

    def concatenate_data_update_hash(self, data):
        """It concatenates data from sender and writes it in file"""
        if self.check_packages_and_crc(data) and self.count < self.amount_of_packages:
            print("Packet was successfully received")
            if self.count == 300:  # 1000 is number of paket. It implemented to not make string too big
                self.f.write(self.all_data)
                self.all_data = b''

            self.hash_code.update(data)
            # self.f.write(data)
            # self.all_data += data
            self.all_data = b''.join([self.all_data, data])
            self.send_success()

            if self.count <= self.amount_of_packages:
                self.count += 1
        else:
            self.send_success_or_error()


# Start
# Creating server. If everything is OK, receive a filename, size and all data
my_server = Server(localIP, localPort, bufferSize)
my_server.bind_server()

my_server.listener()
# my_server.make_file()
my_server.close_socket()
