from random import randint, uniform
import json
from threading import Thread
import socket 
from time import sleep
import struct

PORT = 9999
# BUFFER_SIZE = 64
IP = ""
BUFFER_SIZE = 128

def listen_udp(tplink):
    """
    Opens port to listen for UDP requests
    Responds based on the utilised API
    """
    print(f"Announcing TPLink on UDP port {PORT}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((IP, PORT))

    while True:
        data, address = sock.recvfrom(BUFFER_SIZE)
        print(f"Received from address: {address}")
        response = tplink.commands_api(data, "udp")
        if response:
            print(response)
            sock.sendto(response, address)

def listen_tcp(tplink):
    """
    Opens port to listen for TCP requests
    Responds based on the utilised API
    """
    print(f"TPLink listening for requests on TCP port {PORT}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((IP, PORT))

    while True:
        sock.listen(1)
        conn, _ = sock.accept()
        data = conn.recv(BUFFER_SIZE)
        response = tplink.commands_api(data, "tcp")
        if response:
            conn.sendall(response)
        conn.close()


def encrypt(plaintext, add_suffix=True):
    """
    Encrypts the response messages using
    XOR function per byte with the default starting
    key. Optional header with the length of the packet
    in big-endian 4-byte at start of packet
    """
    key = 171
    byte_array = bytearray()
    byte_array.extend(map(ord, plaintext))
    xored_bytes = []
    if add_suffix:
        prefix_array = struct.pack('>I', len(byte_array))
        xored_bytes.extend(prefix_array)
    for plainbyte in byte_array:
        cipherbyte = plainbyte ^ key 
        key = cipherbyte
        xored_bytes.append(cipherbyte)
    return bytes(xored_bytes)

def decrypt(cipher, strip_suffix=True):
    """
    Encrypts the response messages using
    XOR function per byte with the default starting
    key. Optional header with the length of the packet
    in big-endian 4-byte at start of packet
    """
    ciphertext = cipher
    if strip_suffix:
        ciphertext = cipher[4:]
    key = 171
    buffer = []
    for cipherbyte in ciphertext:
        plainbyte = key ^ cipherbyte
        key = cipherbyte
        buffer.append(plainbyte)
    plaintext = bytes(buffer)
    return plaintext.decode()


def random_mac():
    """Generates a random MAC address for TPLink Vendor"""
    mac = "50:c7:bf"
    delimiter = ":"
    for i in range(0, 6):
        if i % 2 == 0:
            mac = mac + delimiter
        mac = mac + f"{randint(0,15):x}"
    return mac


def generate_id(len):
    """Generates random id of desired length"""
    generatedId = ""
    for _ in range(0, len):
        generatedId = generatedId + f"{randint(0,15):x}"
    return generatedId


def random_latitude():
    """Generates random latitude"""
    minimum = -90
    maxumum = 90
    return round(uniform(minimum, maxumum), 4)


def random_longitude():
    """Generates random longitude"""
    minimum = -180
    maxumum = 180
    return round(uniform(minimum, maxumum), 4)



class TPLink:
    def __init__(self, *, alias="HS110 Mock", model="HS110(UK)", mac=random_mac(), init_relay_state=0, init_led_off=0, init_total=0):
        """Instatiates a TPLink device with given properties and initial states"""
        self.sw_ver = "1.0.8 Build 151113 Rel.24658"
        self.hw_ver = "1.0"
        self.type = "IOT.SMARTPLUGSWITCH"
        self.model = model
        self.dev_name = "Wi-Fi Smart Plug With Energy Monitoring"
        self.icon_hash = ""
        self.on_time = 0
        self.active_mode = "schedule"
        self.feature = "TIM:ENE"
        self.updating = 0
        self.oemId = generate_id(32)
        self.deviceId = generate_id(40)
        self.hwId = generate_id(32)
        self.latitude = random_latitude()
        self.latitude_i = self.latitude * 10000
        self.longitude = random_longitude()
        self.longitude_i = self.longitude * 10000
        self.rssi = -65
        self.err_code = 0
        self.alias = alias
        self.mac = mac 
        self.relay_state = init_relay_state
        self.led_off = init_led_off
        self.current = 0
        self.voltage = 0
        self.power = 0
        self.total = init_total
        self.load_on = False
        self.load_nominals = {
            "power" : 0,
            "voltage" : 0,
            "current" : 0
        }
        self.start_servers()
        self.consumption = Thread(target=self.simulate_consumption, daemon=True)
        self.consumption.start()
        self.commandMap = {
            '{"system":{"get_sysinfo":{}},"cnCloud":{"get_info":{}},"smartlife.iot.common.cloud":{"get_info":{}},"smartlife.cam.ipcamera.cloud":{"get_info":{}}}' : getattr(self, "get_sys_info"),
            '{"system":{"get_sysinfo":{}}}': getattr(self, "get_sys_info"),
            '{"emeter":{"get_realtime":{}}}': getattr(self, "emeter"),
            '{"system":{"set_relay_state":{"state":1}}}': getattr(self, "turn_relay_on"),
            '{"system":{"set_relay_state":{"state":0}}}': getattr(self, "turn_relay_off"),
        }

    def get_sys_info(self, protocol):
        """Responds to '{"system":{"get_sysinfo":{}}}' command"""
        add_suffix = True
        if protocol == "udp":
            add_suffix = False
        response = json.dumps({
            "system": {
                "get_sysinfo": {
                    "sw_ver": self.sw_ver,
                    "hw_ver": self.hw_ver,
                    "type": self.type,
                    "model": self.model,
                    "dev_name": self.dev_name,
                    "icon_hash": self.icon_hash,
                    "relay_state": self.relay_state,
                    "on_time": self.on_time,
                    "active_mode": self.active_mode,
                    "feature": self.feature,
                    "updating": self.updating,
                    "rssi": self.rssi,
                    "led_off": self.led_off,
                    "alias": self.alias,
                    "mac": self.mac,
                    "deviceId": self.deviceId,
                    "hwId": self.hwId,
                    "oemId": self.oemId,
                    "latitude": str(self.latitude),
                    "latitude_i": self.latitude_i,
                    "longitude": str(self.longitude),
                    "longitude_i": self.longitude_i,
                    "err_code": self.err_code
                }
            }
        })
        return encrypt(response, add_suffix=add_suffix)

    def emeter(self, protocol):
        """Responds to '{"emeter":{"get_realtime":{}}}' command"""
        add_suffix = True
        if protocol == "udp":
            add_suffix = False
        response = json.dumps({
            "emeter": {
                "get_realtime":
                    {
                        "current": self.current,
                        "voltage": self.voltage,
                        "power": self.power,
                        "total": self.total,
                        "err_code": self.err_code
                    }
            }
        })
        return encrypt(response, add_suffix=add_suffix)

    def turn_relay_on(self):
        """
        Simulates the toggle relay turn on
        Changes the measurements only if a load is plugged in
        """
        print("Relay toggle on")
        self.relay_state = 1
        if self.load_on:
            self.power = self.load_nominals["power"]
            self.voltage = self.load_nominals["voltage"]
            self.current = self.load_nominals["current"]

    def turn_relay_off(self):
        """
        Simulates the toggle relay turn of
        Changes the measurements to 0
        """
        print("Relay toggle off")
        self.relay_state = 0
        self.power = 0
        self.voltage = 0
        self.current = 0
        
    def simulate_plug_in(self, *, power = 350, voltage = 220, current = 3):
        """
        Simulates the plug in of a device
        Changes the measurements to nominal values
        passed or to default load stats
        """
        self.load_on = True
        print("Load plugged in")
        self.load_nominals["power"] = power
        self.load_nominals["voltage"] = voltage
        self.load_nominals["current"] = current
        if self.relay_state == 1:
            self.power = power
            self.voltage = voltage
            self.current = current

    def simulate_plug_out(self):
        """
        Simulates the plug out of a device
        Changes the measurements to 0
        """
        self.load_on = False
        print("Load plugged out")
        self.load_nominals["power"] = 0
        self.load_nominals["voltage"] = 0
        self.load_nominals["current"] = 0
        self.power = 0
        self.voltage = 0
        self.current = 0


    def start_servers(self):
        """
        Start both servers for UDP
        and TCP port, in the background
        """
        ThreadUDP = Thread(target=listen_udp, args=(self,))
        ThreadTCP = Thread(target=listen_tcp, args=(self,))
        print("Starting Servers")
        ThreadUDP.start()
        ThreadTCP.start()
        print ("Servers Started!")

    def commands_api(self, command, protocol):
        """
        Decryptes the command passed and
        maps to its related function to produce
        a response
        """
        strip_suffix = True
        if protocol == "udp":
            strip_suffix = False
        command = decrypt(command, strip_suffix=strip_suffix)
        try:
            if 'context' in command:
                print(self.commandMap[command['context']['system']])
                return self.commandMap[command['context']['system']](protocol)
            else:
                self.commandMap[command](protocol)
        except KeyError:
            print(f"Not supported command: {command}")
            return None
    
    
    def simulate_consumption(self):
        """
        Starts a loop and calculates next cycle power
        and total energy. If the plug is toggled on
        and has a load on it, power is fluctuated with some random
        way between some thresholds to simulate some real
        power. Energy is increased using the time span of the cycle
        """
        clock = 1 # 1 second is the clock of the system
        while True:
            if self.relay_state == 1 and self.load_on:
                randomised_power = self.power + uniform(-0.05, 0.05) * self.power
                if randomised_power >= self.load_nominals["power"]:
                    randomised_power = self.load_nominals["power"]
                elif randomised_power <= self.load_nominals["power"] * 0.75:
                    randomised_power = self.load_nominals["power"] * 0.75
            
                self.power = round(randomised_power, 3)
                self.total = self.total + (self.power/1000.)/3600
            sleep(clock)
            

    

        

