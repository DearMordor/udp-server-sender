import hashlib
import socket
import zlib

localIP = "192.168.30.38"
targetIP = "192.168.30.38"

localPort = 4023
targetPort = 7110

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
        self.count = 1
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

    def check_packages(self):
        """Checks a current count from sender and compares with local count"""
        if self.counter_from_sender == self.count:
            print("Counters jsou v poho")
            # self.send_success()
            # self.send_bytes("1".encode())
            # print("1 was sent to the client\n")
            self.count += 1
            return 1
        else:
            if self.counter_from_sender < self.count:
                # self.send_success()
                # self.send_bytes("1".encode())
                print("0 was sent to the client")
                return 0
            # self.send_error()
            # self.send_bytes("0".encode())
            # print("0 was sent to the client\n")
            if self.count < 0:
                self.count = 0

            return 0

    def listener(self):
        """Main function listens to data from sender"""
        # f = None
        while True:
            data, addr = self.udp_server_socket.recvfrom(self.buffer_size)
            print(data)
            print('received from: ', addr, 'data: package_' + str(self.count))
            data = self.parse_data(data)
            if data is None:
                self.send_error()
                continue

            if self.count == 1:
                self.get_filename(data)

                if not self.check_packages_and_crc(data):
                    print("Iteration was continued ")
                    continue

                # f = open(self.filename, "wb")

            elif self.count == 2:  # For future, check if data is number
                self.get_size(data)

                if not self.check_packages_and_crc(data):
                    print("Iteration was continued ")
                    continue
            else:
                print("Self count " + str(self.count) + " Sender's amount_of_packages " + str(self.amount_of_packages))
                if self.count == self.amount_of_packages:
                    if self.check_packages_and_crc(data):
                        # print(data)
                        hash_from_sender = get_hash_code(data)
                        print("Hash from sender: " + hash_from_sender)
                        print("My hash " + str(self.hash_code.hexdigest()))
                        if self.compare_hash_codes(hash_from_sender):
                            print("Hash codes are equal!")

                        break

                # if self.check_packages(self.counter_from_sender) != 0 and self.control_crc(data):
                if self.check_packages_and_crc(data):
                    print("All data was concatenated with just data\n")
                    # if self.count == 1000:  # 1000 is number of paket. It implemented to not make string too big
                    #     f.write(self.all_data)
                    #     self.all_data = b''
                    self.hash_code.update(data)
                    self.all_data += data

        # f.close()
        print(self.filename + " was created!")

    def get_filename(self, data):
        self.filename = data.decode("utf-8")
        print("Filename got success: " + self.filename)

    def get_size(self, data):
        try:
            self.amount_of_packages = int(data.decode("utf-8"))
            print("Size got success: " + str(self.amount_of_packages))
        except Exception:
            print("Invalid literal for get_size")

    def make_file(self):
        with open("out/" + self.filename, "wb") as f:
            f.write(self.all_data)
        print("File was created! ")

    def close_socket(self):
        self.udp_server_socket.close()

    def send_bytes(self, data):
        self.udp_server_socket.sendto(data, (targetIP, targetPort))

    def send_error(self):
        msg = str(zlib.crc32(b"BAD")) + "|" + "BAD"
        self.send_bytes(msg.encode())
        print("Error was sent to the client\n")

    def send_success(self):
        msg = str(zlib.crc32(b"GOOD")) + "|" + "GOOD"
        self.send_bytes(msg.encode())
        print("Success was sent to the client\n")

    def parse_data(self, data):
        """Reads input data up to char '|' then return data without chars before the char '|' """
        try:
            data = self.get_package_counter_from_sender(data)

            return self.get_src_from_sender(data)
        except Exception:
            print("Error with parsing data")
            return None

    def control_crc(self, data):
        try:
            self.crc32 = int(self.crc32)
            if self.crc32 == zlib.crc32(data):
                print("Crc je v poho")
            return self.crc32 == zlib.crc32(data)
        except Exception:
            print("Error with crc!")
            return False

    def get_package_counter_from_sender(self, data):
        i = 0
        num = ""
        while data[i] != 124:  # 124 means in ASCII "|"
            num += chr(data[i])
            i += 1

        self.counter_from_sender = int(num)
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

    def check_packages_and_crc(self, data):

        if self.check_packages() == 1 and self.control_crc(data):
            print("WTF ARE YOU SENDING")
            self.send_success()
            return True
        else:
            print("Counter from sender is " + str(self.counter_from_sender))
            print("My counter is " + str(self.count))
            if self.counter_from_sender < self.count:
                self.send_success()
                return False
            # else:
            #     self.send_error()
            #     return False
            # if self.counter_from_sender < self.count:
            #     self.count -= 1
            self.send_error()
            return False


# Start
# Creating server. If everything is OK, receive a filename, size and all data
my_server = Server(localIP, localPort, bufferSize)
my_server.bind_server()

my_server.listener()
my_server.make_file()
my_server.close_socket()
