from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel
import time
import requests

class VideoStreamingTopo(Topo):
    def build(self):
        # Add switches
        s1, s2, s3 = [self.addSwitch('s%d' % n) for n in range(1, 4)]

        # Add servers
        servers = [self.addHost('server%d' % n, ip='10.0.0.%d' % n, mac='00:00:00:00:00:%02x' % n) for n in range(1, 4)]

        # Add clients
        clients = [self.addHost('client%d' % n, ip='10.0.1.%d' % n, mac='00:00:00:00:01:%02x' % n) for n in range(1, 4)]

        # Connect switches
        self.addLink(s1, s2)
        self.addLink(s2, s3)

        # Connect servers to switches
        for server, switch in zip(servers, (s1, s2, s3)):
            self.addLink(server, switch)

        # Connect clients to switches
        for client in clients:
            self.addLink(client, s1)

def prepopulate_arp_tables(net):
    for src_host in net.hosts:
        for dst_host in net.hosts:
            if src_host != dst_host:
                src_host.setARP(ip=dst_host.IP(), mac=dst_host.MAC())

def check_load_balancer_ready(net):
    try:
        response = requests.get('http://10.0.0.2:8080', timeout=1)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False

def run():
    topo = VideoStreamingTopo()
    net = Mininet(topo=topo, controller=lambda name: RemoteController(name, ip='127.0.0.1'))
    net.start()

    # Start the HTTP server on server1, server2, and server3
    server1 = net.get('server1')
    server2 = net.get('server2')
    server3 = net.get('server3')

    server1.cmd('python3 -m http.server 8080 &')
    server2.cmd('python3 -m http.server 8080 &')
    server3.cmd('python3 -m http.server 8080 &')
    
    time.sleep(5)  # Wait for 5 seconds
    
    # Prepopulate ARP tables
    prepopulate_arp_tables(net)

    # Wait for a few seconds
    time.sleep(10)
    
    # Wait for the load balancer to be ready
    while not check_load_balancer_ready(net):
        time.sleep(5)

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
topos = {'VideoStreamingTopo': (lambda: VideoStreamingTopo())}

