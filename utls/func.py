import threading 
import socket 
import time

service_dictionary = {
        20: 'FTP',
        21: 'FTP',
        22: 'SSH',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        443: 'HTTPS',
        1900: 'SSDP',
    }

service_list = ['FTP', 'SSH', 'SMTP', 'DNS', 'HTTP', 'POP3', 'HTTPS', 'SSDP', 'Others']

protocol_dictionary = {
        1: 'ICMP',   # Internet Control Message Protocol
        2: 'IGMP',   # Internet Group Management Protocol
        3: 'GGP',    # Gateway-to-Gateway Protocol
        4: 'IPv4',   # IPv4 encapsulation
        5: 'ST',     # ST datagram mode
        6: 'TCP',    # Transmission Control Protocol
        8: 'EGP',    # Exterior Gateway Protocol
        9: 'IGP',    # Interior Gateway Protocol
        17: 'UDP',   # UDP protocol
        41: 'IPv6',  # IPv6 encapsulation
        89: 'OSPF',  # Open Shortest Path First
    }

protocol_list = ['ICMP', 'IGMP', 'GGP', 'IPv4', 'ST', 'TCP', 'EGP', 'IGP', 'UDP', 'IPv6', 'OSPF', 'Others']

def get_protocal(id):
    '''
    Get the protocal of the port.
    '''
    
    try:
        protocol = protocol_dictionary[id]
    except KeyError:
        protocol = 'Others'
    return protocol

def get_service_by_port(port):
    '''
    Get the service by the port.
    port: the port of the target.
    '''
    assert(port is not None)

    try:
        service = service_dictionary[port]
    except KeyError:
        service = 'Others'
    return service

def packet_count_func(results):
    '''
    Count the number of the packet.
    results: the list of the results.
    '''
    assert(results is not None)
    total_count = 0
    server_dic = {}
    protocol_dic = {}
    for result in results:
        total_count += 1
        if result[5] not in protocol_dic.keys():
            protocol_dic[result[5]] = 1
        else:
            protocol_dic[result[5]] += 1
        if result[5] not in {'TCP', 'UDP'}:   # For application layer, only count the tcp and udp packets
            continue
        if  result[6] not in server_dic.keys():
            server_dic[result[6]] = 1
        else:
            server_dic[result[6]] += 1
    return total_count, protocol_dic, server_dic

def iter2string(ip):
    return f'{ip[0]}.{ip[1]}.{ip[2]}.{ip[3]}'

def filter_by_src_ip(ip_address, results):
    '''
    Filter the results by the source IP address.
    ip_address: the IP address of the target.
    results: the list of the results.
    '''
    assert(ip_address is not None)
    assert(results is not None)
    new_results=  []
    for result in results:
        if result[1] == ip_address:
            new_results.append(result)
    return new_results

def filter_by_dst_ip(ip_address,results):
    '''
    Filter the results by the destination IP address.
    ip_address: the IP address of the target.
    results: the list of the results.
    '''
    assert(ip_address is not None)
    assert(results is not None)
    new_results=  []
    for result in results:
        if result[2] == ip_address:
            new_results.append(result)
    return new_results


def filter_by_src_ip_and_dst_ip(src_ip_address, dst_ip_address, results):
    '''
    Filter the results by the source IP address and the destination IP address.
    src_ip_address: the source IP address of the target.
    dst_ip_address: the destination IP address of the target.
    results: the list of the results.
    '''
    assert(src_ip_address is not None)
    assert(dst_ip_address is not None)
    assert(results is not None)
    new_results = []
    for result in results:
        if result[1] == src_ip_address and result[2] == dst_ip_address:
            new_results.append(result)
    return new_results

def parse_raw_package(ts, data):
    '''
    Parse the raw package.
    ts: the timestamp of the package.
    data: the data of the package.
    '''
    # print(time.strftime('%Y-%m-%d %H:%M:%S', (time.localtime(ts))),data)
    packet = data
    ip_header = packet[0:20]
    from struct import unpack    # unpack the package

    # Unpack the IP header
    iph = unpack('!BBHHHBBH4s4s', ip_header)
    version = (iph[0] & 0xF0) >> 4  # Version
    # ihl = (iph[0] & 0x0F) << 2  # IHL
    # total_length = iph[2]  # Total Length
    # ttl = iph[5]   # TTL
    protocol = iph[6]       # protocol type
    s_addr = socket.inet_ntoa(iph[8])
    d_addr = socket.inet_ntoa(iph[9])

    if protocol == 6:
        # Unpack the TCP header
        tcp_header = packet[20:40]
        tcph = unpack('!HHLLBBHHH', tcp_header)
        source_port = tcph[0]             # Source Port
        dest_port = tcph[1]               # Destination Port
        # sequence = tcph[2]                # Sequence Number
        # acknowledgement = tcph[3]         # Acknowledgement Number
        # doff_reserved = tcph[4]           # Data Offset, Reserved
        # tcph_length = doff_reserved >> 4  # TCP header length
        # length = total_length - 20        # Data length
    elif protocol == 17:
        # Unpack the UDP header
        udp_header = packet[20:28]
        udph = unpack('!HHHH', udp_header)
        source_port = udph[0]             # Source Port
        dest_port = udph[1]               # Destination Port
        # length = udph[2]                  # Length
        # checksum = udph[3]                # Checksum
        # service determine by the port, if the src or dst port is not in the dictionary, then it is 'Others'
        
    else :
        source_port = 'Unknown'
        dest_port = 'Unknown'
        
    service = get_service_by_port(dest_port)
    if service == 'Others':
        service = get_service_by_port(source_port)
    return  time.strftime('%Y-%m-%d %H:%M:%S', (time.localtime(ts))), s_addr, d_addr, str(source_port), str(dest_port) ,get_protocal(protocol), service, "IPv"+str(version)  

def get_ip_address(hostname=None):
    '''
    Get the IP address of the hostname.
    hostname: the hostname of the target.
    '''
    assert(hostname is not None)
    try:
        ip_address = socket.gethostbyname(hostname)
    except socket.gaierror:
        ip_address = 'Unknown'
    return ip_address

def capture_packet(device, ip_address, event, task_list):
    '''
    Capture the packet of the target.
    device: the device of the target.
    ip_address: the IP address of the target.
    event: the event of the target.
    task_list: the list of the task.
    '''
    assert(device is not None)
    assert(ip_address is not None)
    assert(event is not None)
    assert(task_list is not None)
    while True:
        if event.is_set():
            ts = time.time()  # Get the timestamp of the package.
            try:
                packet = device.recvfrom(65535)   
                print(len(task_list))
                task = ThreadWorker(ts, packet[0])
                task_list.append(task)   # add the task to the list
                task.setDaemon(True)     # if the Daemon is set to True, the thread will be terminated when the main thread is terminated
                task.start()             # start the thread and begin to parse the raw package
            except socket.timeout:
                print(time.strftime('%Y-%m-%d %H:%M:%S', (time.localtime(ts))),'No data captured')
        else:
            return 

class ThreadWorker(threading.Thread):
    '''
    define the method for multi-thread to parse the raw package.
    '''
    def __init__(self, ts, data):
        super(ThreadWorker, self).__init__()
        self.result = None
        self.ts = ts
        self.data = data

    def run(self):
        self.result = parse_raw_package(self.ts, self.data)

    def get_result(self):
        return self.result

class MainIPCaptureWorker(threading.Thread):
    def __init__(self, device, ip_address, event):
        '''
        device: the device of the target.
        ip_address: the ip address of the target.
        event: the event to be set when the task is done.
        '''
        super(MainIPCaptureWorker, self).__init__()
        self.device = device
        self.ip_address = ip_address
        self.event = event
        self.task_list = []

    def run(self):
        capture_packet(self.device, self.ip_address, self.event, self.task_list)

    def get_task_list(self):
        return self.task_list
    
    def get_result(self):
        return [worker.get_result() for worker in self.task_list]

if __name__ == '__main__':
    '''
    Test the function.
    '''
    print(get_protocal('1'))
    print(get_ip_address(socket.gethostname()))
    print(get_ip_address('www.baidu.com'))
    print(get_ip_address('www.google.com'))
    print(get_ip_address('www.microsoft.com'))


    ip_address = get_ip_address(socket.gethostname())
    device = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    device.settimeout(1)
    device.bind((ip_address,0))
    device.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    device.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    event = threading.Event()
    event.set()
    worker = MainIPCaptureWorker(device, ip_address, event)
    worker.start()
    results = worker.get_result()
    print(results)