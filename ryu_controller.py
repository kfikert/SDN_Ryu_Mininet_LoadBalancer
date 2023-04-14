import json
import random
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp
from ryu.lib.packet import arp as arp_proto
from ryu.lib.packet import ether_types

class LoadBalancer(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    current_server = 0
    
    def __init__(self, *args, **kwargs):
        super(LoadBalancer, self).__init__(*args, **kwargs)
        self.mac_to_port = {} 
        self.ip_to_mac = {
            '10.0.0.1': '00:00:00:00:00:01',
            '10.0.0.2': '00:00:00:00:00:02',
            '10.0.0.3': '00:00:00:00:00:03',
        }
        self.server_load = {ip: 0 for ip in self.server_ips}
        self.round_robin_index = 0

    def get_out_port(self, datapath, src, server_mac, in_port):
        dpid = datapath.id
        if server_mac in self.ip_to_mac.values():
            server_index = random.randint(0, len(self.server_ips) - 1)

        # Choose the next server in the list using Round Robin
        selected_server = self.server_ips[self.next_server]
        self.next_server = (self.next_server + 1) % len(self.server_ips)
        print(f"Selected server index: {server_index}")
        # Get the MAC address of the selected server
        server_mac = self.ip_to_mac[selected_server]
        
        # Get the out_port for the selected server
        out_port = self.mac_to_port[dpid][server_mac]
        print(f"Output port for server: {out_port}")
        return out_port
    def __init__(self, *args, **kwargs):
        super(LoadBalancer, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.ip_to_mac = {
            '10.0.0.2': '00:00:00:00:00:02',
            '10.0.0.3': '00:00:00:00:00:03',
        }
        self.server_ips = list(self.ip_to_mac.keys())
        self.next_server = 0
        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install default rule to send to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath, 0, match, actions)
        print(f"Default flow added for switch {datapath.id}")

    def add_flow(self, datapath, priority, match, actions):
        print(f"Adding flow: {datapath.id}, {priority}, {match}, {actions}")
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        print("Packet-In event received")
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
            if ipv4_pkt:
                dst_ip = ipv4_pkt.dst
                src = eth.src
                if dst_ip in self.server_ips: # If destination is server
                    print("Destination IP belongs to a server")
                    # Chose the next server using Round Robin - 130423
                    server_ip = self.server_ips[self.current_server]
                    server_mac = self.ip_to_mac[server_ip]
                    print(f"Before get_out_port(): dpid={datapath.id}, src={src}, server_mac={server_mac}, in_port={in_port}")
                    out_port = self.mac_to_port[datapath.id][server_mac]
                    print(f"After get_out_port(): out_port={out_port}")
                    actions = [parser.OFPActionOutput(out_port)]

                    # Update current server index for the next request
                    self.current_server = (self.current_server + 1) % len(self.server_ips)
                else:
                    print(f"Destination IP ({dst_ip}) does not belong to a server. Server IPs: {self.server_ips}")
            return

        src = eth.src
        dst = eth.dst


        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # Learn a MAC address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install a flow to avoid packet-in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                              in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)

        # Print information for debugging
        print("Packet-In - Switch: {}, Src: {}, Dst: {}, InPort: {}, OutPort: {}".format(dpid, src, dst, in_port, out_port))

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            arp_pkt = pkt.get_protocol(arp_proto.arp)
            if arp_pkt.opcode == arp_proto.ARP_REQUEST:
                self.handle_arp(datapath, arp_pkt, in_port)

        tcp_pkts = pkt.get_protocols(tcp.tcp)
        if not tcp_pkts:
            return
        tcp_pkt = tcp_pkts[0]
        print("TCP:", tcp_pkt)
        print("TCP packet received")
        if not tcp_pkt:  # If not TCP packet, ignore
            return
            
        ip_pkts = pkt.get_protocols(ipv4.ipv4)
        
        if ip_pkts:
            ip_pkt = ip_pkts[0]
            dst_ip = ip_pkt.dst
            src_ip = ip_pkt.src

            print(f"Handling packet: {pkt}")

            if dst_ip in self.server_ips:  # If destination self server
                print("Handling packet destined to server")
                actions = [parser.OFPActionOutput(in_port)]  # Reverse the direction
                match = parser.OFPMatch(in_port=datapath.ofproto.OFPP_LOCAL, eth_type=0x0800, ipv4_src=dst_ip, ipv4_dst=src_ip)
                print("Adding flow for server:", match)
                self.add_flow(datapath, 1, match, actions)

            else:  # If destination is a client
                print("Handling packet destined to client")
                self.current_server = (self.current_server + 1) % len(self.server_ips)
                selected_server = self.server_ips[self.current_server]
                actions = [parser.OFPActionSetField(ipv4_dst=selected_server), parser.OFPActionOutput(datapath.ofproto.OFPP_LOCAL)]
                match = parser.OFPMatch(in_port=in_port, eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip, tcp_dst=tcp_pkt.dst)
                print("Adding flow for client:", match)
                self.add_flow(datapath, 1, match, actions)  # Corrected line
                
    def handle_arp(self, datapath, arp_pkt, in_port):
        if arp_pkt.dst_ip not in self.server_ips:
            return

        selected_server_ip = self.server_ips[self.current_server]
        selected_server_mac = self.ip_to_mac[selected_server_ip]
        self.current_server = (self.current_server + 1) % len(self.server_ips)

        arp_reply_pkt = packet.Packet()
        arp_reply_pkt.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_ARP,
                                                     src=selected_server_mac,
                                                     dst=arp_pkt.src_mac))
        arp_reply_pkt.add_protocol(arp_proto.arp(opcode=arp_proto.ARP_REPLY,
                                                 src_mac=selected_server_mac,
                                                 src_ip=arp_pkt.dst_ip,
                                                 dst_mac=arp_pkt.src_mac,
                                                 dst_ip=arp_pkt.src_ip))
        arp_reply_pkt.serialize()

        actions = [datapath.ofproto_parser.OFPActionOutput(in_port)]
        out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,
                                                   buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                                                   in_port=datapath.ofproto.OFPP_CONTROLLER,
                                                   actions=actions,
                                                   data=arp_reply_pkt.data)
        datapath.send_msg(out)

