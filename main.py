"""
Author: Oleg Shkolnik יא9.
Description: program receives ip and checks how many opened ports there are on this ip sorting trough them from 20 to 1024.
Date: 1/03/24
"""


from scapy.all import *


getting_ports = list()
test_ip = '127.0.0.1'
test_port = 80


def checking_ack_packet(syn_ack_packet):
    """
    function checks if packet that we received from the server is ack packet
    :param syn_ack_packet: packet that function checks
    :return: true or false
    """
    return syn_ack_packet.haslayer(TCP) and syn_ack_packet[TCP].flags == 0x12


def main(destination_ip):
    """
    loop that checks ports from 20 to 1024
    :param destination_ip: ip we work with
    :print: list of ports that are opened
    """
    destination_port = 20
    try:
        while destination_port <= 1024:
            syn_packet = IP(dst=destination_ip) / TCP(dport=destination_port, flags="S")

            syn_ack_packet = sr1(syn_packet, timeout=0.5, verbose=False)

            if syn_ack_packet:

                if checking_ack_packet(syn_ack_packet):  # 0x12 = SYN-ACK
                    print(f'SYN packet sent successfully. Received SYN-ACK packet on the port {destination_port}')
                    getting_ports.append(destination_port)

            destination_port += 1

        print(f'Opened ports are {getting_ports}')
    except socket.error as err:
        """
        Send the name of error in error situation
        """
        print('Received socket error ' + str(err))


if __name__ == "__main__":
    """
    sending SYN packet on the closed port to check that function works
    """
    packet = IP(dst=test_ip) / TCP(dport=test_port, flags="S")
    res_packet = sr1(packet, verbose=False)
    assert not checking_ack_packet(res_packet)

    ip = input('Please input ip you want to check: ')
    main(ip)
