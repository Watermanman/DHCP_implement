#!/usr/bin/env python3

import argparse, socket,random,struct,uuid
from datetime import datetime


def getMAC():
    myuuid=uuid.uuid1()
    macb=myuuid.node.to_bytes(6,'big')
    return macb
    # mac=str(hex(uuid.getnode()).replace('0x',''))
    # while len(mac)<12:
    #     mac+='0'+mac
    # temp=''
    # macb=b''
    # for i in range(12):
    #     temp+=mac[i]
    #     if i%2!=0:
    #         macb+=struct.pack('!B',int(temp,16))
    #         temp=''



class dhcp_packet:
    def __init__(self):
        self.macaddr=getMAC()   #get Hardware Address
        self.XID=b''
        for i in range(4):
            # temp=random.randint(0,255)
            self.XID+=struct.pack('!B',random.randint(0,255))

    def build(self):
        house=b''
        house+=b'\x01'      #OP(client->server)
        house+=b'\x01'      #HTYPE(ethernet)
        house+=b'\x06'      #HLEN(ethernet)
        house+=b'\x00'      #HOPS
        house+=self.XID     #XID(init random)
        house+=b'\x00\x00'  #SECS
        house+=b'\x80\x00'  #FLAGS(left first bit=1,server send bordcast)
        house+=b'\x00'*4    #CIADDR(client IP)
        house+=b'\x00'*4    #YIADDR(server distribute IP)
        house+=b'\x00'*4    #GIADDR
        house+=b'\x00'*4    #GIADDR
        house+=self.macaddr #CHADDR(MAC address from client) 
        house+=b'\x00'*10   #Padding zero for CHADDR
        house+=b'\x00'*192  #BOOTP(sname(64)+file(128)) 
        house+=b'\x63\x82\x53\x63'  #Magic Cookie(DHCP)
        # house+=b'\x35\x01\x01'              #Option53(option53,length=1,type=1(discover))  type=1(discover)2(offer)3(request)5(ACK)
        # house+=b'\x3d\x07\x01'+self.macaddr #Option61(option61,length=7,type=1,MACaddress)
        # house+=b'\x32\x04'+b'\x00'*4        #Option50(option50,length=4,IP address)
        # house+=b'\x37\x04\x01\x03\x06\x2a'  #Option55(option55,length=4,Paraneter Request(4byte))
        # house+=b'\xff'                      #Option255(Option end)
        # house+=b'\x00'*7                    #Padding
        return house

def server(port):
    print ('in server')
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST,1)
    sock.bind(('',67))
    packet=dhcp_packet()
    print('server is working...{}'.format(sock.getsockname()))
    #------------------wait Discover--------------------
    waitDiscover=True
    while waitDiscover:
        getDiscover,(remotehost,remoteport)=sock.recvfrom(1024)
        if (getDiscover):
            waitDiscover=False
    print('Receive Discover,already to send offer...')
    #------------------send Offer------------------------
    # offerdata=packet.build()
    offerdata=getDiscover
    offerdata=offerdata[1:]
    offerdata=b'\x02'+offerdata
    seg1=offerdata[:16]
    seg2=offerdata[20:]
    offerdata=seg1+b'\xc0\xa8\x64\x01'+seg2
    offerdata=offerdata[:-4]
    offerdata+=b'\x35\x01\x02\xff'   #Option(option53,length=1,type=2(offer),optionEnd)
    sock.sendto(offerdata, ('<broadcast>',68))
    print('Offer send, wait for Request....')
    #------------------wait Request----------------------
    waitRequest=True
    while waitRequest:
        getRequest,(remotehost,remoteport)=sock.recvfrom(1024)
        if(getRequest):
            waitRequest=False
    print('Receive Request,already to send ACK...') 
    #--------------------send ACK-----------------------
    ACKdata=getRequest
    ACKdata=ACKdata[1:]
    ACKdata=b'\x02'+ACKdata
    ACKdata=ACKdata[:-4]
    ACKdata+=b'\x35\x01\x05\xff'   #Option(option53,length=1,type=5(ACK),optionEnd)
    sock.sendto(ACKdata, ('<broadcast>',68))
    print('ACK send.')
    #---------------------------------------------------- 
    

def client(port):
    print('in client')
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST,1)
    sock.bind(('',68))
    packet=dhcp_packet()
    #-----------------send Discover----------------------
    discoverdata=packet.build()
    # discoverdata=discoverdata[1:]
    # discoverdata=b'\x01'+discoverdata
    discoverdata+=b'\x35\x01\x01\xff'   #Option(option53,length=1,type=1(discover),optionEnd)
    sock.sendto(discoverdata, ('<broadcast>',67))
    print('Discover send, wait for offer....')
    #-----------------wait Offer -----------------------
    waitOffer=True
    while waitOffer:
        recvdata,IPinfo=sock.recvfrom(1024)    
        if(recvdata):
            if(discoverdata[4:8]==recvdata[4:8]) and (recvdata[0]==2):   #check XID,OP...more check
                waitOffer=False
    print('Getting Offer!!')
    YIADDR=recvdata[16:20] #get16~19
    print ('Disbrute IP: '+str(YIADDR[0])+'.'+str(YIADDR[1])+'.'+str(YIADDR[2])+'.'+str(YIADDR[3]))
    #-------------------send Request---------------------
    requestdata=packet.build()
    requestdata+=b'\x35\x01\x03\xff'   #Option(option53,length=1,type=3(request),optionEnd)
    sock.sendto(requestdata, ('<broadcast>',67))
    print('Request send, wait for ACK....')
    #---------------------wait ACK ----------------------
    waitACK=True
    while waitACK:
        getACK,(remotehost,remoteport)=sock.recvfrom(1024)
        if(getACK):
            waitACK=False
    print('Receive ACK, done!!') 
 
    #----------------------------------------------------
    



if __name__ == '__main__':
    choices = {'client': client, 'server': server}
    parser = argparse.ArgumentParser(description='DHCP Implement')
    parser.add_argument('role', choices=choices, help='which role to play')
    parser.add_argument('-p', metavar='PORT', type=int, default=68,help='DHCP port')
    args = parser.parse_args()
    function = choices[args.role]
    function(args.p)
