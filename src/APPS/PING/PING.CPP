/*

   mTCP Ping.cpp
   Copyright (C) 2009-2026 Michael B. Brutman (mbbrutman@gmail.com)
   mTCP web page: http://www.brutman.com/mTCP


   This file is part of mTCP.

   mTCP is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   mTCP is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with mTCP.  If not, see <http://www.gnu.org/licenses/>.


   Description: Ping application

   Changes:

   2012-04-29: Fix a small bug; outgoing packets were too large
   2011-05-27: Initial release as open source software
   2015-01-18: Minor change to Ctrl-Break and Ctrl-C handling.
   2015-02-03: Code cleanup
   2026-09-07: Change to read the 8253 counter instead of reprogramming it.

*/


// Return codes
//   0 - All good, and all sent packets received a response
//   1 - Usage error
//   2 - DNS error
//   3 - No responses received
//   4 - Some responses received
//


#include <conio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "types.h"
#include "trace.h"
#include "utils.h"
#include "packet.h"
#include "arp.h"
#include "udp.h"
#include "dns.h"
#include "timer.h"
#include "trace.h"


#define PACKET_COUNT_DEFAULT    (4)
#define PACKET_PAYLOAD_DEFAULT (32)

char    *ServerName;
IpAddr_t ServerAddr;
uint16_t PacketCount = PACKET_COUNT_DEFAULT;
uint16_t PacketPayload = PACKET_PAYLOAD_DEFAULT;

uint16_t TimeoutSecs = 1;

bool Audible = false;

uint16_t PacketsSent = 0;
uint16_t RepliesReceived = 0;
uint16_t RepliesLost = 0;

uint32_t ReplyTime = 0;
uint32_t ReplyMin = 0xffffffff;
uint32_t ReplyMax = 0;

uint16_t icmpLen;




// Ctrl-Break and Ctrl-C handler.  Check the flag once in a while to see if
// the user wants out.

volatile uint8_t CtrlBreakDetected = 0;

void __interrupt __far ctrlBreakHandler( ) {
  CtrlBreakDetected = 1;
}




IcmpEchoPacket_t icmpEchoPacket;


// Flag that indicates a new response has arrived.
bool ResponseReceived = false;

// TTL and IP of the last response
uint8_t LastTTL = 0;
IpAddr_t LastIp = { 0, 0, 0, 0 };


// Function prototypes

void timerModeDetector( void );
void icmpHandler( const unsigned char *packet, const IcmpHeader *icmp );
void sendAndWait( void );
void parseArgs( int argc, char *argv[] );
void shutdown( int rc );




static char *CopyrightMsg= "\nmTCP Ping by M Brutman (mbbrutman@gmail.com) (C)opyright 2009-2026\nVersion: " __DATE__ "\n";


int main( int argc, char *argv[] ) {

  puts( CopyrightMsg );

  parseArgs( argc, argv );


  // Initialize TCP/IP
  if ( Utils::parseEnv( ) != 0 ) {
    exit( 1 );
  }


  // No sockets, no buffers TCP buffers
  if ( Utils::initStack( 0, 0, ctrlBreakHandler, ctrlBreakHandler ) ) {
    puts( "\nFailed to initialize TCP/IP - exiting" );
    exit( 1 );
  }

  // From this point forward you have to call the shutdown( ) routine to
  // exit because we have the timer interrupt hooked.

  timerModeDetector( );

  // Start resolving the name.
  Dns::resolve( ServerName, ServerAddr, 1 );

  while ( !CtrlBreakDetected && Dns::isQueryPending( ) ) {
    Utils::processPackets( );
    Dns::drivePendingQuery( );
  }


  // Query is no longer pending or we bailed out of the loop.
  if ( Dns::resolve( ServerName, ServerAddr, 0 ) != 0 ) {
    printf( "Error resolving server name: %s\n", ServerName );
    shutdown( 2 );
  }


  if ( Ip::isSame( ServerAddr, MyIpAddr ) || (ServerAddr[0] == 127) ) {
    puts( "Pinging your own address or loopback addresses is not supported." );
    shutdown( 1 );
  }


  printf( "Sending ICMP packets to %u.%u.%u.%u\n"
          "ICMP Packet payload is %u bytes.\n\n",
          ServerAddr[0], ServerAddr[1], ServerAddr[2], ServerAddr[3],
          PacketPayload);


  // Register Icmp handler
  Icmp::icmpCallback = icmpHandler;


  // Build up our packet

  icmpLen = PacketPayload + sizeof( IcmpHeader ) + sizeof( uint16_t ) * 2;


  // Eth header source and type
  icmpEchoPacket.eh.setSrc( MyEthAddr );
  icmpEchoPacket.eh.setType( 0x0800 );


  // Ip Header
  icmpEchoPacket.ip.set( IP_PROTOCOL_ICMP, ServerAddr, icmpLen, 0, 0 );

  // Icmp header
  icmpEchoPacket.icmp.type = ICMP_ECHO_REQUEST;
  icmpEchoPacket.icmp.code = 0;
  icmpEchoPacket.icmp.checksum = 0;

  // Icmp data

  icmpEchoPacket.ident = 0x6048; // Will be 4860 when transmitted; the PCjr model number
  icmpEchoPacket.seq = 0;

  for ( int i=0; i < PacketPayload; i++ ) {
    icmpEchoPacket.data[i] = (i % 26) + 'A';
  }

  // Icmp checksum
  //icmpEchoPacket.icmp.checksum = Ip::genericChecksum( (uint16_t *)&icmpEchoPacket.icmp, icmpLen );
  icmpEchoPacket.icmp.checksum = ipchksum( (uint16_t *)&icmpEchoPacket.icmp, icmpLen );



  // Eth header dest - has to be called after Ip header is set.
  // Should return a 1 the first time because we haven't ARPed yet.
  int8_t arpRc = icmpEchoPacket.ip.setDestEth( icmpEchoPacket.eh.dest );



  // Wait for ARP response

  clockTicks_t startTime = TIMER_GET_CURRENT( );

  while ( arpRc ) {

    if ( Timer_diff( startTime, TIMER_GET_CURRENT( ) ) > TIMER_MS_TO_TICKS( 4000 ) ) {
      break;
    }

    Utils::processPackets( );

    arpRc = icmpEchoPacket.ip.setDestEth( icmpEchoPacket.eh.dest );

  }

  if ( arpRc ) {
    puts( "Timeout waiting for ARP response." );
    shutdown( 3 );
  }


  // At this point we ARPed and got a response.  Time to start sending
  // packets.

  sendAndWait( );

  if ( PacketCount > 1 ) {

    for ( uint16_t l = 1; l < PacketCount; l++ ) {

      if ( CtrlBreakDetected ) break;

      // Setup the packet.
      icmpEchoPacket.icmp.checksum = 0;
      icmpEchoPacket.seq = htons( l );
      //icmpEchoPacket.icmp.checksum = Ip::genericChecksum( (uint16_t *)&icmpEchoPacket.icmp, icmpLen );
      icmpEchoPacket.icmp.checksum = ipchksum( (uint16_t *)&icmpEchoPacket.icmp, icmpLen );

      sendAndWait( );

    }

  }

  printf( "\nPackets sent: %u, Replies received: %u, Replies lost: %u\n",
          PacketsSent, RepliesReceived, RepliesLost );

  if ( RepliesReceived ) {

    uint32_t big = ( ReplyTime / RepliesReceived ) / 10lu;
    uint32_t small = ( ReplyTime / RepliesReceived ) % 10;

    printf( "Round trip time min / avg / max = %lu.%01lu / %lu.%01lu / %lu.%01lu\n",
             ReplyMin/10, ReplyMin%10, big, small, ReplyMax/10, ReplyMax%10 );
  }

  int rc = 4;
  if ( PacketsSent == RepliesReceived ) {
    rc = 0;
  } else if ( RepliesReceived == 0 ) {
    rc = 3;
  }

  shutdown( rc );

  return 0;
}


// ---------------------------------------------------------------------------
//
// Timer stuff
//
// Instead of reprogramming the timer to increment the BIOS tick faster and
// counting those fast ticks, directly read the timer again.  This is nicer
// because we don't have to reprogram the 8253 or hook the hardware timer
// interrupt, and we can still get great precision.  (Even better than our
// previous code, which with reprogramming the timer was only getting 0.85ms
// granularity.


// These constants assume the machine is using 8253 timer mode 2.

uint16_t TimerOneMs = TIMER_8253_ONE_MS;
uint16_t TimerTenthMs = TIMER_8253_ONE_MS / 10;

void timerModeDetector( void ) {

  int modeDetected = Timer_modeDetector( );

  if ( modeDetected == 3 ) {
    TimerTenthMs = TimerTenthMs << 1;
    TimerOneMs = TimerOneMs << 1;
  }

  TRACE(("Ping: Timer mode %d detected\n", modeDetected));

}




// Called by the low level Icmp Handler.  Check to see if this is the
// reply we are waiting for, and if so set a flag to indicate victory.

void icmpHandler( const unsigned char *packet, const IcmpHeader *icmp ) {

  if ( icmp->type == ICMP_ECHO_REPLY ) {

    IcmpEchoPacket_t *icmpReply = (IcmpEchoPacket_t *)packet;

    if ( icmpReply->ident == 0x6048 && icmpReply->seq == icmpEchoPacket.seq ) {

      // More checks ..

      uint16_t icmpPayloadLen = icmpReply->ip.payloadLen( ) - sizeof(IcmpHeader) - sizeof(uint16_t) * 2;

      if ( icmpPayloadLen == PacketPayload && memcmp(icmpReply->data, icmpEchoPacket.data, PacketPayload) == 0 ) {
        ResponseReceived = true;
        LastTTL = icmpReply->ip.ttl;
        Ip::copy( LastIp, icmpReply->ip.ip_src );
      }

    }

  }

}


void sendAndWait( ) {

  PacketsSent++;

  ResponseReceived = false;

  // You can get multiple responses when doing a broadcast ping.
  int16_t RepliesThisIteration = 0;

  // Don't have to worry about a minimul length - icmpEchoPacket is guaranteed to be
  // bigger than 60 bytes.
  Packet_send_pkt( &icmpEchoPacket, icmpLen + sizeof(EthHeader) + sizeof(IpHeader) );

  // Precompute the timeout value to avoid an expensive 32 multiply each
  // time through the loop.  It needs to be 32 bits because 16 bits only covers
  // up to 6 seconds.
  uint32_t timeout_10ths = TimeoutSecs * 10000l;

  uint32_t tenths_ms = 0;
  uint16_t startTime = readTimer_8253( );

  while ( 1 ) {

    if ( CtrlBreakDetected ) return;

    Utils::processPackets( );

    uint16_t c = readTimer_8253( );
    uint16_t e = startTime - c;

    // More than one tenth of a millisecond?
    if ( e > (TimerTenthMs) ) {

      while ( e > TimerTenthMs ) {
        tenths_ms += 1;
        e = e - (TimerTenthMs);
      }

      // Add the remainder back onto the starting time so we include it next time.
      startTime = c + e;

    }

    if ( ResponseReceived ) {

      printf( "Packet sequence number %u received from %u.%u.%u.%u in %lu.%01lu ms, ttl=%u\n",
              ntohs( icmpEchoPacket.seq ),
              LastIp[0], LastIp[1], LastIp[2], LastIp[3],
              tenths_ms/10, tenths_ms%10, LastTTL );

      RepliesThisIteration++;
      RepliesReceived++;
      ReplyTime += tenths_ms;
      if ( ReplyMin > tenths_ms ) ReplyMin = tenths_ms;
      if ( ReplyMax < tenths_ms ) ReplyMax = tenths_ms;

      // Playing this sound costs 50ms, so be careful where you place this code.
      if (Audible) { sound(500); delay(50); nosound( ); }

      ResponseReceived = 0;
    }


    // Wait a full second for replies to come in.  Reset the timer each time we
    // get a response so we break the loop one second after the last response
    // appears, or after one second if no responses appear.

    if ( tenths_ms > timeout_10ths ) {

      if ( RepliesThisIteration == 0 ) {
        printf( "Packet sequence number %u: timeout!\n", ntohs( icmpEchoPacket.seq ) );
        RepliesLost++;
      }

      break;
    }

  }

}



void usage( void ) {
  printf( "\nping [options] <ipaddr>\n\n"
        "Options:\n"
        "  -help        Shows this help\n"
        "  -a           Audible ping\n"
        "  -count <n>   Number of packets to send, default is %u\n"
        "  -size <n>    Size of ICMP payload to send, default is %u, max is %u\n"
        "  -timeout <n> Number of seconds to wait for a response packet\n",
        PACKET_COUNT_DEFAULT, PACKET_PAYLOAD_DEFAULT, ICMP_ECHO_OPT_DATA);
  exit( 1 );
}


void parseArgs( int argc, char *argv[] ) {

  int i=1;
  for ( ; i<argc; i++ ) {

    if ( argv[i][0] != '-' ) break;

    if ( stricmp( argv[i], "-help" ) == 0 ) {
      usage( );
    }
    else if ( stricmp( argv[i], "-count" ) == 0 ) {
      i++;
      if ( i == argc ) {
        usage( );
      }
      PacketCount = atoi( argv[i] );
      if ( PacketCount == 0 ) {
        puts( "Bad parameter for -count" );
        usage( );
      }
    }
    else if ( stricmp( argv[i], "-size" ) == 0 ) {
      i++;
      if ( i == argc ) {
        usage( );
      }
      PacketPayload = atoi( argv[i] );
      if ( PacketPayload > ICMP_ECHO_OPT_DATA ) {
        printf( "Bad parameter for -size: Limit is %u\n", ICMP_ECHO_OPT_DATA );
        usage( );
      }
    }
    else if ( stricmp( argv[i], "-timeout" ) == 0 ) {
      i++;
      if ( i == argc ) {
        usage( );
      }
      TimeoutSecs = atoi( argv[i] );
      if ( TimeoutSecs == 0 ) {
        puts( "Bad parameter for -timeout: Should be greater than 0" );
        usage( );
      }
    }
    else if ( strcmp( argv[i], "-a" ) == 0 ) {
      Audible = true;
    }
    else {
      printf( "Unknown option: %s\n", argv[i] );
      usage( );
    }

  }

  if ( i == argc ) {
    puts( "A machine name or IP address is required." );
    usage( );
  }

  ServerName = argv[i];

}





void shutdown( int rc ) {
  Utils::endStack( );
  exit( rc );
}
