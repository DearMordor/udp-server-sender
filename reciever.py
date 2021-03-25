import hashlib
import socket
import zlib

localIP = "192.168.30.25"
localPort = 4023
bufferSize = 1024


def get_hash_code(data):
    return data.decode()


class Server:
    """
    UDP server for PSIA.
    author: Nurkozhin Arlan
    """

    def __init__(self, ip_address, port, buffer_size):
        self.ip_address = ip_address
        self.port = port
        self.buffer_size = buffer_size
        self.filename = ''
        self.udp_server_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.count = 0
        self.all_data = b''
        self.amount_of_packages = -1
        self.counter_from_sender = 0
        self.crc32 = 0
        self.hash_code = hashlib.md5()

    def bind_server(self):
        """Binds server with sender via sockets"""
        self.udp_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.udp_server_socket.bind((self.ip_address, self.port))
        print("Server runs and listens!")

    def check_packages(self, count_from_sender):
        """Checks a current count from sender and compares with local count"""
        self.count += 1
        if count_from_sender == self.count:
            self.send_bytes("1".encode())
            print("1 was sent to the client")
            return 1
        else:
            if count_from_sender < self.count:
                self.send_bytes("1".encode())
                print("1 was sent to the client")
                return 1
            self.send_bytes("0".encode())
            print("0 was sent to the client")
            self.count -= 1
            if self.count < 0:
                self.count = 0
            return 0

    def listener(self):
        """Main function listens to data from sender"""
        while True:
            data, addr = self.udp_server_socket.recvfrom(self.buffer_size)
            print('received from: ', addr, 'data: package_' + str(self.count))
            data = self.parse_data(data)
            print(data)

            if self.count == 0:
                self.get_filename(data)
                print("Filename got success: " + self.filename)

                if self.control_packages_and_crc(data):
                    print("Iteration was continued ")
                    continue

            elif self.count == 1:  # For future, check if data is number
                self.get_size(data)
                print("Size got success: " + str(self.amount_of_packages))

                if self.control_packages_and_crc(data):
                    print("Iteration was continued ")
                    continue
            else:
                if self.check_packages(self.counter_from_sender) != 0 and self.control_crc(data) == True:
                    print("All data was concatenated with just data")
                    self.hash_code.update(data)
                    self.all_data += data

            if self.count == self.amount_of_packages:
                break

        data, addr = self.udp_server_socket.recvfrom(self.buffer_size)
        data = self.parse_data(data)
        if self.check_packages(self.counter_from_sender) != 0 and self.control_crc(data) == True:
            print(data)
            print("Got a hashcode from " + str(addr))
            hash_from_sender = get_hash_code(data)
            print("Hash from sender: " + hash_from_sender)
            print("My hash " + str(self.hash_code.hexdigest()))
            if self.compare_hash_codes(hash_from_sender):
                print("Hash codes are equal!")

    def get_filename(self, data):
        self.filename = data.decode("utf-8")

    def get_size(self, data):
        self.amount_of_packages = int(data.decode("utf-8"))

    def make_file(self):
        with open("out/" + self.filename, "wb") as f:
            f.write(self.all_data)
        print("File was created! ")

    def close_socket(self):
        self.udp_server_socket.close()

    def send_bytes(self, data):
        self.udp_server_socket.sendto(data, ("192.168.30.38", 7110))

    def parse_data(self, data):
        """Reads input data up to char '|' then return data without chars before the char '|' """
        data = self.get_package_counter_from_sender(data)

        return self.get_src_from_sender(data)

    def control_crc(self, data):
        print("My crc " + str(zlib.crc32(data)) + "\nSender's crc: " + str(self.crc32))
        self.crc32 = int(self.crc32)
        if self.crc32 == zlib.crc32(data):
            print("Crc is fine")
        return self.crc32 == zlib.crc32(data)

    def control_packages_and_crc(self, data):
        return self.check_packages(self.counter_from_sender) == 0 or not self.control_crc(data)

    def get_package_counter_from_sender(self, data):
        i = 0
        num = ""
        while data[i] != 124:  # 124 means in ASCII "|"
            num += chr(data[i])
            i += 1

        self.counter_from_sender = int(num)
        print("Counter from sender is " + str(self.counter_from_sender))
        i += 1
        return data[i:]

    def get_src_from_sender(self, data):
        i = 0
        crc = ""
        while data[i] != 124:  # 124 means in ASCII "|"
            crc += chr(data[i])
            i += 1
        i += 1
        self.crc32 = int(crc)
        return data[i:]

    def compare_hash_codes(self, hash_code_from_sender):
        return hash_code_from_sender == self.hash_code.hexdigest()


# Start
# Creating server. If everything is OK, receive a filename, size and all data
my_server = Server(localIP, localPort, bufferSize)
my_server.bind_server()

my_server.listener()
my_server.make_file()
my_server.close_socket()
