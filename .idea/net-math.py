#!/usr/bin/env python

'''
Module contains a number of functions related to network-based mathematics
and conversions.
'''
import socket, struct

def ip_to_binary(ip):
    binary = socket.inet_aton(ip)
    return struct.unpack('!L', binary)[0]

def binary_to_ip(binary):

    return socket.inet_ntoa(struct.pack('!L', binary))
