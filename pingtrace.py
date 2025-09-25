"""
Author: Christine Thatcher
Course: CS372 - Intro to Networking
Date: March 11, 2025

*** CITATION: Skeleton code provided by OSU course instructional staff. ***

Description:
This program is organized around two primary classes: IcmpHelperLibrary and IcmpPacket. 
The IcmpHelperLibrary class serves as the main interface and handles high-level functionality 
such as initiating ping requests and traceroute operations, calculating RTT metrics, and 
processing ICMP error codes. The nested IcmpPacket class is responsible for the detailed 
construction and parsing of individual ICMP packets, including managing packet headers, payloads, 
checksum calculations, and encoding. Lastly, the IcmpPacket_EchoReply class exists to parse 
and validate incoming ICMP reply packets, verifying consistency in sequence numbers, identifiers, 
and data payloads. Overall, this works to ensure the integrity of responses received.

"""

# Imports
import os
import sys              # for accepting command line args
from socket import *
import struct
import time
import select


class IcmpHelperLibrary:

    # IcmpHelperLibrary Class Scope Variables:

    # Constants:
    __DEBUG_IcmpHelperLibrary = False                   # Allows for debug output
    PING_REQ_COUNT = 4                                  # Number of packets sent for standart ping request
    TRACEROUT_MAX_TRIES = 3                             # Max number of times traceroute will send a dup packet

    # Attributes:
    roundTripTimes = []
    packetsSent = 0
    packetsRecvd = 0

    """
    References:
    https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml 
    """ 
        
    #  IcmpErrorCodes Class scope variables
    icmpErrorTypes = {
        3: {
            0: "Net Unreachable",
            1: "Host Unreachable",
            2: "Protocol unreachable",
            3: "Port unreachable",
            4: "Fragmentation Needed and Don't Fragment was Set",
            5: "Source Route Failed",
            6: "Destination Network Unknown",
            7: "Destination Host Unknown",
            8: "Source Host Isolated",
            9: "Communication with Destination Network is Administratively Prohibited",
            10: "Communication with Destination Host is Administratively Prohibited",
            11: "Destination Network Unreachable for Type of Service",
            12: "Destination Host Unreachable for Type of Service", 
            13: "Communication Administratively Prohibited",
            14: "Host Precedence Violation",
            15: "Precedence cutoff in effect"
        },
        11: {
            0: "Time to Live exceeded in Transit",
            1: "Fragment Reassembly Time Exceeded"
        }
    }

    """
    -----------------------------------------------------------------------------------------
    Private methods:
    """
    def __sendIcmpTraceRoute(self, host):
        print("sendIcmpTraceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        sequenceNumber = 0

        while True:
            replyRecvd = False
            icmpType, icmpCode = (None, None)

            for i in range(self.TRACEROUT_MAX_TRIES):
                
                icmpPacket = IcmpHelperLibrary.IcmpPacket()
                icmpPacket.setTtl(sequenceNumber + 1)
                randomIdentifier = (os.getpid() & 0xffff)
                icmpPacket.buildPacket_echoRequest(randomIdentifier, sequenceNumber)
                icmpPacket.setIcmpTarget(host)
                icmpType, icmpCode = icmpPacket.sendEchoRequest()

                if icmpType != -1:
                    replyRecvd = True
                    break
            
            # Print out packet type description
            if self.errorFound(icmpType):
                codeDescription = self.getCodeDescription(icmpType, icmpCode)
                print(f"ICMP Reply received.\tDescription: {codeDescription}")

            # If no reply has been received, then move on to the next hop
            if not replyRecvd:
                print(f"  MAXIMUM ATTEMPTS reached for packet with TTL: {sequenceNumber+1}. Moving on to TTL: {sequenceNumber + 2}...")            

            # If destination is reached
            if icmpType == 0:
                break
                
            sequenceNumber += 1
        
        # Get and print out RTT metrics
        rttMetrics = self.getRttMetrics(multiplier=1000)
        packetLossRate = self.calculatePacketLossRate()
        self.__printEndOfRunReport(rttMetrics, packetLossRate)

    
    def __sendIcmpEchoRequest(self, host):
        print("sendIcmpEchoRequest Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        
        # Ping sends 4 requests by default, change in class scope:
        for i in range(self.PING_REQ_COUNT):
            # Build packet
            icmpPacket = IcmpHelperLibrary.IcmpPacket()

            randomIdentifier = (os.getpid() & 0xffff)      # Get as 16 bit number - Limit based on ICMP header standards
                                                           # Some PIDs are larger than 16 bit

            packetIdentifier = randomIdentifier
            packetSequenceNumber = i

            icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)  # Build ICMP for IP payload
            icmpPacket.setIcmpTarget(host)
            icmpPacket.sendEchoRequest()                                                # Build IP

            # DEBUG print the packet header and packet if debug flag is set
            icmpPacket.printIcmpPacketHeader_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            icmpPacket.printIcmpPacket_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            
            icmpType = icmpPacket.getIcmpType()
            icmpCode = icmpPacket.getIcmpCode()

            # check if an error occured, and print out a message describing the error
            if self.errorFound(icmpType):
                codeDescription = self.getCodeDescription(icmpType, icmpCode)
                self.printErrorMessage(icmpType, icmpCode, codeDescription)

        # Get and print out RTT metrics
        rttMetrics = self.getRttMetrics(multiplier=1000)
        packetLossRate = self.calculatePacketLossRate()
        self.__printEndOfRunReport(rttMetrics, packetLossRate)
    
    def __printEndOfRunReport(self, metrics, packetLossRate):
        print("\nEND OF PING/TRACEROUTE  ---------------------------------------------------- ")
        print("\nRTT Metrics:")
        for key, value in metrics.items():
            print(f"{key}: {value:.4f} ms", end="\t")
        
        # Print blank line for formatting
        print()

        # Print the packet loss rate
        print(f"\nThe packet loss rate was: {packetLossRate:.2f}%\n")


    """
    -----------------------------------------------------------------------------------------
    Public methods:
    """
    def sendPing(self, targetHost):
        print("ping Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpEchoRequest(targetHost)

    def traceRoute(self, targetHost):
        """
        Use the traceRoute() function and update the __sendIcmpTraceRoute() function to 
        handle sending ICMP echo requests with increasing TTL values and processing the 
        responses to trace the route to the destination.
        """
        print("traceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpTraceRoute(targetHost)
    
    def calculatePacketLossRate(self):
        """ Calculates and returns the packet loss rate as a percentage. """
        return ((self.packetsSent - self.packetsRecvd) / self.packetsSent) * 100
    
    def getRttMetrics(self, multiplier=1):
        """ Calculates min, max, and avg (in SECONDS by default!) and returns a dict. """
        numRttEntries = len(self.roundTripTimes)
        if numRttEntries == 0:
            return None
        
        sumRtt = multiplier * sum(self.roundTripTimes)
        avgRtt = sumRtt / numRttEntries
        
        return {
            "Minimum": min(self.roundTripTimes) * multiplier,
            "Maximum": max(self.roundTripTimes) * multiplier,
            "Average": avgRtt
        }
    
    def errorFound(self, packetType):
            """ Returns bool value for if an error type was found. """
            return packetType in self.icmpErrorTypes
        
    def getCodeDescription(self, packetType, packetCode):
        """ Returns a string with the error type description. """
        if packetType in self.icmpErrorTypes and packetCode in self.icmpErrorTypes[packetType]:
            return self.icmpErrorTypes[packetType][packetCode]
        
    def printErrorMessage(self, icmpType, icmpCode, errorDescription):
        print("ERROR detected. ICMP type: {}, ICMP code: {}, Description: {}".format(icmpType, icmpCode, errorDescription))



    class IcmpPacket:
        # IcmpPacket Class Scope Variables

        __icmpTarget = ""                       # Remote Host
        __destinationIpAddress = ""             # Remote Host IP Address
        __header = b''                          # Header after byte packing
        __data = b''                            # Data after encoding
        __dataRaw = ""                          # Raw string data before encoding
        __icmpType = 0                          # Valid values are 0-255 (unsigned int, 8 bits)
        __icmpCode = 0                          # Valid values are 0-255 (unsigned int, 8 bits)
        __packetChecksum = 0                    # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetIdentifier = 0                  # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetSequenceNumber = 0              # Valid values are 0-65535 (unsigned short, 16 bits)
        __ipTimeout = 10
        __ttl = 255                             # Time to live

        __DEBUG_IcmpPacket = False              # Allows for debug output

        """
        -----------------------------------------------------------------------------------------
        Getters:
        """
        def getIcmpTarget(self):
            return self.__icmpTarget

        def getDataRaw(self):
            return self.__dataRaw

        def getIcmpType(self):
            return self.__icmpType

        def getIcmpCode(self):
            return self.__icmpCode

        def getPacketChecksum(self):
            return self.__packetChecksum

        def getPacketIdentifier(self):
            return self.__packetIdentifier

        def getPacketSequenceNumber(self):
            return self.__packetSequenceNumber

        def getTtl(self):
            return self.__ttl

        """
        -----------------------------------------------------------------------------------------
        Setters:
        """
        def setIcmpTarget(self, icmpTarget):
            self.__icmpTarget = icmpTarget

            # Only attempt to get destination address if it is not whitespace
            if len(self.__icmpTarget.strip()) > 0:
                self.__destinationIpAddress = gethostbyname(self.__icmpTarget.strip())

        def setIcmpType(self, icmpType):
            self.__icmpType = icmpType

        def setIcmpCode(self, icmpCode):
            self.__icmpCode = icmpCode

        def setPacketChecksum(self, packetChecksum):
            self.__packetChecksum = packetChecksum

        def setPacketIdentifier(self, packetIdentifier):
            self.__packetIdentifier = packetIdentifier

        def setPacketSequenceNumber(self, sequenceNumber):
            self.__packetSequenceNumber = sequenceNumber

        def setTtl(self, ttl):
            self.__ttl = ttl

        """
        -----------------------------------------------------------------------------------------
        Private methods:
        """
        def __recalculateChecksum(self):
            print("calculateChecksum Started...") if self.__DEBUG_IcmpPacket else 0
            packetAsByteData = b''.join([self.__header, self.__data])
            checksum = 0

            # This checksum function will work with pairs of values with two separate 16 bit segments. Any remaining
            # 16 bit segment will be handled on the upper end of the 32 bit segment.
            countTo = (len(packetAsByteData) // 2) * 2

            # Calculate checksum for all paired segments
            print(f'{"Count":10} {"Value":10} {"Sum":10}') if self.__DEBUG_IcmpPacket else 0
            count = 0
            while count < countTo:
                thisVal = packetAsByteData[count + 1] * 256 + packetAsByteData[count]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture 16 bit checksum as 32 bit value
                print(f'{count:10} {hex(thisVal):10} {hex(checksum):10}') if self.__DEBUG_IcmpPacket else 0
                count = count + 2

            # Calculate checksum for remaining segment (if there are any)
            if countTo < len(packetAsByteData):
                thisVal = packetAsByteData[len(packetAsByteData) - 1]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture as 32 bit value
                print(count, "\t", hex(thisVal), "\t", hex(checksum)) if self.__DEBUG_IcmpPacket else 0

            # Add 1's Complement Rotation to original checksum
            checksum = (checksum >> 16) + (checksum & 0xffff)   # Rotate and add to base 16 bits
            checksum = (checksum >> 16) + checksum              # Rotate and add

            answer = ~checksum                  # Invert bits
            answer = answer & 0xffff            # Trim to 16 bit value
            answer = answer >> 8 | (answer << 8 & 0xff00)
            print("Checksum: ", hex(answer)) if self.__DEBUG_IcmpPacket else 0

            self.setPacketChecksum(answer)

        def __packHeader(self):
            # The following header is based on http://www.networksorcery.com/enp/protocol/icmp/msg8.htm
            # Type = 8 bits
            # Code = 8 bits
            # ICMP Header Checksum = 16 bits
            # Identifier = 16 bits
            # Sequence Number = 16 bits
            self.__header = struct.pack("!BBHHH",
                                   self.getIcmpType(),              #  8 bits / 1 byte  / Format code B
                                   self.getIcmpCode(),              #  8 bits / 1 byte  / Format code B
                                   self.getPacketChecksum(),        # 16 bits / 2 bytes / Format code H
                                   self.getPacketIdentifier(),      # 16 bits / 2 bytes / Format code H
                                   self.getPacketSequenceNumber()   # 16 bits / 2 bytes / Format code H
                                   )

        def __encodeData(self):
            data_time = struct.pack("d", time.time())               # Used to track overall round trip time
                                                                    # time.time() creates a 64 bit value of 8 bytes
            dataRawEncoded = self.getDataRaw().encode("utf-8")

            self.__data = data_time + dataRawEncoded

        def __packAndRecalculateChecksum(self):
            # Checksum is calculated with the following sequence to confirm data in up to date
            self.__packHeader()                 # packHeader() and encodeData() transfer data to their respective bit
                                                # locations, otherwise, the bit sequences are empty or incorrect.
            self.__encodeData()
            self.__recalculateChecksum()        # Result will set new checksum value
            self.__packHeader()                 # Header is rebuilt to include new checksum value

        def __validateIcmpReplyPacketWithOriginalPingData(self, icmpReplyPacket):
            """
            Takes in a IcmpPacket_EchoReply object, and validates fields compared to the 
            original response. Checks sequence number, identifier, and data. 

            If any discrepancies are found, the overall __isValidResponse field is set to False. 
            """

            icmpReplyPacket.expectedIdentifier = self.getPacketIdentifier()
            icmpReplyPacket.expectedSeqNumber = self.getPacketSequenceNumber()
            icmpReplyPacket.expectedDataRaw = self.getDataRaw()

            # Keep track of the validity of the reply packet
            validReply = True

            # Check the Sequence number of the reply compared to request. Update the reply's SeqNum validity
            if icmpReplyPacket.getIcmpSequenceNumber() != self.getPacketSequenceNumber():
                icmpReplyPacket.setIsValidSeqNum(False)
                validReply = False
            
            # Check the Identifier of the reply compared to request. Update the reply's Id validity
            if icmpReplyPacket.getIcmpIdentifier() != self.getPacketIdentifier():
                icmpReplyPacket.setIsValidIdentifier(False)
                validReply = False
            
            # Check the data of the reply compared to request. Update the reply's data validity 
            if icmpReplyPacket.getIcmpData() != self.getDataRaw():
                icmpReplyPacket.setIsValidRawData(False)
                validReply = False

            # Set the overall validity of the reply
            icmpReplyPacket.setIsValidResponse(validReply)

        """
        -----------------------------------------------------------------------------------------
        Public methods:
        """
        def buildPacket_echoRequest(self, packetIdentifier, packetSequenceNumber):
            self.setIcmpType(8)
            self.setIcmpCode(0)
            self.setPacketIdentifier(packetIdentifier)
            self.setPacketSequenceNumber(packetSequenceNumber)
            self.__dataRaw = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            self.__packAndRecalculateChecksum()

        def sendEchoRequest(self):
            if len(self.__icmpTarget.strip()) <= 0 or len(self.__destinationIpAddress.strip()) <= 0:
                self.setIcmpTarget("127.0.0.1")

            print("Pinging (" + self.__icmpTarget + ") " + self.__destinationIpAddress)

            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            mySocket.settimeout(self.__ipTimeout)
            mySocket.bind(("", 0))
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', self.getTtl()))  # Unsigned int - 4 bytes
            try:
                mySocket.sendto(b''.join([self.__header, self.__data]), (self.__destinationIpAddress, 0))
                timeLeft = 30
                pingStartTime = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                endSelect = time.time()
                howLongInSelect = (endSelect - startedSelect)
                
                # Add one to packetSent
                IcmpHelperLibrary.packetsSent += 1
                
                if whatReady[0] == []:  # Timeout
                    print("  *        *        *        *        *    Request timed out.")
                    return -1, -1
                
                recvPacket, addr = mySocket.recvfrom(1024)  # recvPacket - bytes object representing data received
                # addr  - address of socket sending data
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect

                # Update the IcmpHelperLibrary variables to include info from this exchange
                rtt  = timeReceived - pingStartTime
                IcmpHelperLibrary.roundTripTimes.append(rtt)

                if timeLeft <= 0:
                    print("  *        *        *        *        *    Request timed out (By no remaining time left).")
                    return -1, -1

                else:
                    # Fetch the ICMP type and code from the received packet
                    icmpType, icmpCode = recvPacket[20:22]
                    
                    # Update the number packets received:
                    IcmpHelperLibrary.packetsRecvd += 1

                    if icmpType == 11:                          # Time Exceeded
                        print("  TTL=%d\t\tRTT=%.0f ms\t\tType=%d\t\tCode=%d\t\t%s" %
                                (
                                    self.getTtl(),
                                    (timeReceived - pingStartTime) * 1000,
                                    icmpType,
                                    icmpCode,
                                    addr[0]
                                )
                              )

                    elif icmpType == 3:                         # Destination Unreachable
                        print("  TTL=%d\t\tRTT=%.0f ms\t\tType=%d\t\tCode=%d\t\t%s" %
                                  (
                                      self.getTtl(),
                                      (timeReceived - pingStartTime) * 1000,
                                      icmpType,
                                      icmpCode,
                                      addr[0]
                                  )
                              )

                    elif icmpType == 0:                         # Echo Reply
                        icmpReplyPacket = IcmpHelperLibrary.IcmpPacket_EchoReply(recvPacket)
                        self.__validateIcmpReplyPacketWithOriginalPingData(icmpReplyPacket)
                        icmpReplyPacket.printResultToConsole(self.getTtl(), timeReceived, addr)

                    else:
                        print("error")
                    return icmpType, icmpCode
            
            except timeout:
                print("  *        *        *        *        *    Request timed out (By Exception).")
                return -1, -1
            finally:
                mySocket.close()

        def printIcmpPacketHeader_hex(self):
            print("Header Size: ", len(self.__header))
            for i in range(len(self.__header)):
                print("i=", i, " --> ", self.__header[i:i+1].hex())

        def printIcmpPacketData_hex(self):
            print("Data Size: ", len(self.__data))
            for i in range(len(self.__data)):
                print("i=", i, " --> ", self.__data[i:i + 1].hex())

        def printIcmpPacket_hex(self):
            print("Printing packet in hex...")
            self.printIcmpPacketHeader_hex()
            self.printIcmpPacketData_hex()


    class IcmpPacket_EchoReply:
        """
        References:
        http://www.networksorcery.com/enp/protocol/icmp/msg0.html 
        """
        __recvPacket = b''
        __isValidResponse = False



        def __init__(self, recvPacket):
            self.__recvPacket = recvPacket
            self.__IcmpSeqNumber_isValid = True
            self.__IcmpIdentifier_isValid = True
            self.__IcmpRawData_isValid = True

            self.expectedIdentifier = None
            self.expectedSeqNumber = None
            self.expectedDataRaw = None


        """ 
        -----------------------------------------------------------------------------------------
        Getters:
        """
        def getIcmpType(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[20:20 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 20)

        def getIcmpCode(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[21:21 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 21)

        def getIcmpHeaderChecksum(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[22:22 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 22)

        def getIcmpIdentifier(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[24:24 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 24)

        def getIcmpSequenceNumber(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[26:26 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 26)

        def getDateTimeSent(self):
            # This accounts for bytes 28 through 35 = 64 bits
            return self.__unpackByFormatAndPosition("d", 28)   # Used to track overall round trip time
                                                               # time.time() creates a 64 bit value of 8 bytes

        def getIcmpData(self):
            # This accounts for bytes 36 to the end of the packet.
            return self.__recvPacket[36:].decode('utf-8')

        def isValidResponse(self):
            return self.__isValidResponse

        def getIsValidSeqNumber(self):
            return self.__IcmpSeqNumber_isValid
        
        def getIsValidIdentifier(self):
            return self.__IcmpIdentifier_isValid
        
        def getIsValidRawData(self):
            return self.__IcmpRawData_isValid

        """
        -----------------------------------------------------------------------------------------
        Setters:
        """
        def setIsValidResponse(self, booleanValue):
            self.__isValidResponse = booleanValue

        def setIsValidSeqNum(self, booleanValue):
            self.__IcmpSeqNumber_isValid = booleanValue

        def setIsValidIdentifier(self, booleanValue):
            self.__IcmpIdentifier_isValid = booleanValue

        def setIsValidRawData(self, booleanValue):
            self.__IcmpRawData_isValid = booleanValue

        """
        -----------------------------------------------------------------------------------------
        Private Methods:
        """
        def __unpackByFormatAndPosition(self, formatCode, basePosition):
            numberOfbytes = struct.calcsize(formatCode)
            return struct.unpack("!" + formatCode, self.__recvPacket[basePosition:basePosition + numberOfbytes])[0]

        """
        -----------------------------------------------------------------------------------------
        Public Methods:
        """
        def printResultToConsole(self, ttl, timeReceived, addr):
            """
            Prints the reply's ttl, rtt, type, code, identifier, sequence number, and origin ip.
            If reply is invalid, prints the invalid field's expected and received value.
            """
            bytes = struct.calcsize("d")
            timeSent = struct.unpack("d", self.__recvPacket[28:28 + bytes])[0]
            print("  TTL=%d\t\tRTT=%.0f ms\t\tType=%d\t\tCode=%d\t\tIdentifier=%d\t\tSequence Number=%d\t\t%s" %
                  (
                      ttl,
                      (timeReceived - timeSent) * 1000,
                      self.getIcmpType(),
                      self.getIcmpCode(),
                      self.getIcmpIdentifier(),
                      self.getIcmpSequenceNumber(),
                      addr[0]
                  )
                 )
            
            # If the reply is invalid, print which fields are inconsistent 
            if not self.isValidResponse():
                if not self.getIsValidIdentifier():
                    print("Invalid Identifier. Expected ID: {}, Received ID: {}".format(self.expectedIdentifier, self.getIcmpIdentifier()))
                if not self.getIsValidSeqNumber():
                    print("Invalid Sequence Number. Expected: {}, Received: {}".format(self.expectedSeqNumber, self.getIcmpSequenceNumber()))
                if not self.getIsValidRawData():
                    print("Invalid Data. Expected: {}, Received: {}".format(self.expectedDataRaw, self.getIcmpData()))


def main():
    """
    Entry point for the program. Arguments can be provided on the command line. 
    As an example, use the format to ping www.google.com: 
        % python3 IcmpHelperLibrary.py ping "www.google.com"
    
    Alternatively, uncomment one or more of the sendPing/traceRoute calls below.
    """

    icmpHelperPing = IcmpHelperLibrary()

    args = sys.argv
    numArgs = len(args)

    # If invalid args are given, print message and return:
    if numArgs > 3 or numArgs == 2:
        printArgsError()
        return
    
    # If too few (but some) args are given, print message and return:
    elif numArgs == 3:
        destination = args[2]
        if args[1] == "ping":
            icmpHelperPing.sendPing(destination)
        elif args[1] == "traceroute":
            icmpHelperPing.traceRoute(destination)
        else:
            printArgsError()
        return
    
    # No commands given, run one of these instead:
    elif numArgs == 1:
        
        # TODO Choose one of the following by uncommenting out the line:

        # icmpHelperPing.sendPing("209.233.126.254")
        # icmpHelperPing.sendPing("www.google.com")
        # icmpHelperPing.sendPing("gaia.cs.umass.edu")
        # icmpHelperPing.traceRoute("gaia.cs.umass.edu")
        # icmpHelperPing.traceRoute("164.151.129.20")
        # icmpHelperPing.traceRoute("122.56.99.243")
        # icmpHelperPing.traceRoute("www.ratp.fr")
        # icmpHelperPing.traceRoute("www.europa.eu")

        return

    else:
        printArgsError()

def printArgsError():
    """ Prints a message to the console informing the user that the args given are not valid, 
    or that there are missing args."""

    print("Invalid request or arguments given. Try again with the format: python3 <ping/traceroute> <destination ip/domain>")



if __name__ == "__main__":
    main()
