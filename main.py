import re
import asyncio
from dnslib import *
import socket
import argparse


class DNSServer:
    def __init__(self, host, port):
        self.port = port
        self.host = host
        self.root_server_ip = '198.41.0.4'
        self.dns_port = 53
        self.loop = None

    def run(self):
        self.loop = asyncio.get_event_loop()
        self.loop.run_until_complete(self.start_server())

    async def start_server(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind((self.host, self.port))
        print(f'Server start at {(self.host, self.port)}')
        while True:
            data, address = server.recvfrom(4096)
            print(f'Connection from {address}')
            response = await self.handle_client_data(data)
            server.sendto(DNSRecord.pack(response), address)

    async def handle_client_data(self, data):
        response = await self.decide_dns_response(data)
        return response

    async def decide_dns_response(self, data):
        data = DNSRecord.parse(data)
        if '.multiply.' in str(data.q.qname):
            numbers = str(data.q.qname).split('.multiply')[0].split('.')
            X = 1
            for el in numbers:
                X *= int(el)
            response = DNSRecord(DNSHeader(data.header.id, qr=1, rd=0),
                                 a=RR(rname=data.q.qname, rdata=A(f'127.0.0.{X % 256}')))
        else:
            response = await self.get_dns_response(data)
        return response

    async def make_dns_request(self, data, server_ip):
        dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            dns_socket.sendto(data.pack(), (server_ip, self.dns_port))
            response = dns_socket.recv(4096)
            dns_socket.close()
            return DNSRecord.parse(response)
        except socket.error:
            return None

    async def get_dns_response(self, data):
        domain = data.q.qname
        qtype = data.q.qtype
        id = data.header.id
        request = DNSRecord(DNSHeader(id, qr=0, rd=0),
                            q=DNSQuestion(qname=domain, qtype=qtype), )
        response = await self.make_dns_request(request, self.root_server_ip)
        while response:
            if response.header.a:
                for answer in response.rr:
                    if answer.rtype == 1 and answer.rname == domain:
                        print(response)
                        print()
                        print('то что отправляю потом->')
                        print(DNSRecord.pack(response))
                        response.ar.clear()
                        response.auth.clear()
                        return response
                ips = list(filter(lambda x: ':' not in x, extract_dns_inf(str(response.rr))))
                response = self.make_dns_request(request, ips[0])
            elif response.ar:
                ips = list(filter(lambda x: ':' not in x, extract_dns_inf(str(response.ar))))
                response = await self.make_dns_request(request, ips[0])
            elif response.auth:
                auth = extract_dns_inf(str(response.auth))
                auth_request = DNSRecord(DNSHeader(id, qr=0, rd=0),
                                         q=DNSQuestion(qname=auth[0], qtype=qtype), )
                response = await self.make_dns_request(auth_request, auth[0])
            if not response:
                return request


def extract_dns_inf(dns_data):
    inf = re.findall(r"rdata='(.+?)'", dns_data)
    return inf


def init_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', dest='port', action='store', type=int, default=5005)
    parser.add_argument('-host', dest='host', action='store', default='127.0.0.1')
    return parser.parse_args()


def main():
    args = init_parser()
    server = DNSServer(args.host, args.port)
    server.run()


if __name__ == '__main__':
    main()
