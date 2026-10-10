/*

   mTCP HTTPServ HttpServ.cpp
   Copyright (C) 2014-2026 Michael B. Brutman (mbbrutman@gmail.com)
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


   Description: The main part of the http server ...

*/


#include <assert.h>
#include <dos.h>
#include <conio.h>
#include <ctype.h>
#include <fcntl.h>
#include <io.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <malloc.h>

#include "types.h"

#include "timer.h"
#include "trace.h"
#include "utils.h"
#include "packet.h"
#include "arp.h"
#include "tcp.h"
#include "tcpsockm.h"
#include "udp.h"

#include "httpserv.h"
#include "client.h"
#include "screen.h"
#include "dircache.h"
#include "fcache.h"

#ifdef SNTP_CLIENT
#include "dns.h"
#include "sntplib.h"
#endif



// Todo:
//
// When operating with a single client maybe don't hold the connection open?
// More mime types and allow user to edit mime types
// Cache control headers?
// Better on screen activity messages
// Fill in Page for active users?
// Blocking by IP or IP range
// Statistics:
//  - by IP
//  - Last set of transactions
//  - By HTTP return code
//  - By client types
//  - Referrers
// Redirects table?
// Allow custom 404 messages?
// Add logrolling including disk space free function
// TCP counter for dropped new sockets?
// Add support for other HTTP methods.  (At least error them out.)
// Scan for illegal characters in the HTTP request header before parsing.
// Gather some stats on request size; also analyze my existing data





// Function prototypes

void    parseArgs( int argc, char *argv[] );
int8_t  getCfgOpts( void );
int16_t readRealms( void );
void    shutdown( int rc );

void    readRequest( Client *target );
void    serveStatusPage( Client *target );
void    serveClientsPage( Client *target );
void    serveFileOrDirectory( Client *target );
void    forceAllClientsClosed( void );

#ifdef KEYBOARD_COMMANDS
char  * readKeyboardString( void );
#endif

void    sendStatusUDP( void );


// Global vars and flags

uint16_t MaxClients = 0;
uint16_t LclPort = 0;
uint16_t DirCacheSize = 16384;
bool     DirectoryIndexingAllowedDefault = false;

char ServerName[SERVER_NAME_SIZE];             // What name does our server report in responses?
char HTTPDocs[DOS_MAX_PATH_LENGTH];            // Root directory to serve from
char HTTPZips[DOS_MAX_PATH_LENGTH];            // Alternative directory for precompressed content

char RealmsFilename[DOS_MAX_PATHFILE_LENGTH];
char *RealmsMap = NULL;

uint32_t Content_Long_Expires_Time = 86400ul;  // One day

char *GA_Script = NULL;

int8_t Shutdown_Hour = -1;
int8_t Shutdown_Minute = -1;


// UDP logging

typedef struct {
  UdpPacket_t udpHdr;                 // Space for Ethernet, IP and UDP headers
  char payload[UDP_LOGGING_PAYLOAD];  // Log message
} UDP_log_packet_t;

UDP_log_packet_t Udp_lp;
IpAddr_t UDP_target_addr = { 0, 0, 0, 0 }; // Invalid IP address
uint16_t UDP_target_port = 0;


#ifdef SNTP_CLIENT
// SNTP Client

// This is a reasonable length for an SNTP server name
char     SNTPServerName[SERVER_NAME_SIZE];

// The address of the server, once resolved by DNS.
IpAddr_t SNTPServerAddr;

// Used when deciding on when to re-resolve the DNS name of the SNTP server.
uint16_t SntpRequestCounter;
#endif


// Variables shared with the screen/log handler

uint32_t  SessionCounter = 0;
uint32_t  ObjectsServed = 0;
uint16_t  ActiveClients = 0;
uint8_t   Verbosity = 1;
bool      BeepToggle = false;

char      LogFilename[DOS_MAX_PATHFILE_LENGTH];
char     *LogFileBuffer = NULL;
uint16_t  LogFileBufferBytes = 0;
FILE     *LogFile = NULL;
bool      LogFilePaused = false;


// Stats

uint32_t HTTP_RC_200 = 0;
uint32_t HTTP_RC_301 = 0;
uint32_t HTTP_RC_304 = 0;
uint32_t HTTP_RC_400 = 0;
uint32_t HTTP_RC_401 = 0;
uint32_t HTTP_RC_403 = 0;
uint32_t HTTP_RC_404 = 0;
uint32_t HTTP_RC_414 = 0;
uint32_t HTTP_RC_500 = 0;


uint8_t Shutdown = 0;

time_t StartTime;
char StartTimeString[26];

uint8_t DOS_major, DOS_minor;
char BIOSDate[9];

const char *MachineTypeString;
const char *CPUTypeString;






// Ctrl-Break and Ctrl-C handler.  Check the flag once in a while to see if
// the user wants out.

volatile uint8_t CtrlBreakDetected = 0;

void __interrupt __far ctrlBreakHandler( ) {
  CtrlBreakDetected = 1;
}



static const char *machineNames[] = {
  "PC",
  "PC XT",
  "PCjr",
  "PC AT",
  "Unknown"
};

static const char *cpuNames[] = {
  "8088",
  "80286",
  "80386",
  "80486+"
};


void detectMachineDetails( void ) {

  uint16_t dosv = dosVersion( );
  DOS_major = dosv & 0xff;
  DOS_minor = dosv >> 8;

  char far * biosDate_p = (char far *)MK_FP( 0xf000, 0xfff5 );

  memcpy( BIOSDate, biosDate_p, 8 );

  int digits = 0;
  for ( int i=0; i < 8; i++ ) {
    if ( isdigit( BIOSDate[i] ) ) digits++;
  }
  if ( !isdigit( BIOSDate[2] ) && !isdigit( BIOSDate[5] ) && (digits == 6) ) {
    BIOSDate[8] = 0;
  }
  else {
    strcpy( BIOSDate, "UNKNOWN" );
  }

  uint8_t machineTypeByte = *((uint8_t far *)MK_FP( 0xf000, 0xfffe ));

  if (machineTypeByte == 0xFF ) {
    MachineTypeString = machineNames[0];
  } else if (machineTypeByte == 0xFE ) {
    MachineTypeString = machineNames[1];
  } else if (machineTypeByte == 0xFD ) {
    MachineTypeString = machineNames[2];
  } else if (machineTypeByte == 0xFC ) {
    MachineTypeString = machineNames[3];
  } else {
    MachineTypeString = machineNames[4];
  }

  CPUTypeString = cpuNames[ getCPUType( ) ];
}



#ifdef SNTP_CLIENT
void sntpClient( SntpLib::Callback_data_t d ) {
  // Fixme: Consider adding a keyboard shortcut to force a sync.
  if ( d.diffSecs >= 5 ) {
    SntpLib::setDosDateTime( );
    addToScreen( MSG_NORM, "System time updated.\n" );
  }
  addToScreen( MSG_NORM, "SNTP reported a %lu.%03u second difference.\n", d.diffSecs, d.diffMs );
}
#endif



const char *DocRootMsgTemplate = 
  "The %s needs to be a fully qualified directory including the drive.\n"
  "letter. The directory you specified does not exist or has the wrong format.\n"
  "\nSpecified directory: \"%s\"\n";

// isPathValidForServing
//
// This is a highly specific routine that checks to see if a passed in path
// is a valid directory.  The path must start with a DOS drive letter.
// If the path has a trailing slash it will be removed, as we are going
// to use this string as the prefix for whatever URL the user specifies.
//
// This is only intended to be called with HTTPDocs and HTTPZips as the
// arguments, and only at startup.
//
// The parsing here doesn't look for every possible error.  If it gets
// through the stat function we are fine.

bool isPathValidForServing( char *path ) {

  // Use a copy in case we need to display an error message.
  char c[DOS_MAX_PATH_LENGTH];
  strcpy(c, path);

  // The path must start with a drive letter and a path.  The path must
  // be an absolute path, so it must start with a directory delimiter char.
  // If there is no drive letter or it is not an absolute path, reject it.

  if ( !isalpha( c[0] ) || (c[1] != ':') ) return false;

  // Sleazy hack for usability - add the delimiter if they didn't specify it.
  if ( c[2] == 0 ) {
    c[2] = '\\';
    c[3] = 0;
  }

  if ( (c[2] != '\\') && (c[2] != '/') ) return false;

  // Stupid DOS trick: to identify the root directory of the drive as a
  // directory you need the directory delimiter.  But if you end a directory
  // with the directory delimiter stat will not identify it as a directory.
  // So remove any trailing directory delimiter, unless it is the root
  // directory.

  if ( c[3] != 0 ) {

    // This is not a root directory; remove any trailing delimiter.
    char *tmp = c;
    while ( *tmp ) tmp++;
    tmp--;
    if ( *tmp == '/' || *tmp == '\\' ) *tmp = 0;

  }

  // Now we can stat it.

  struct stat statbuf;
  int rc = stat( c, &statbuf );
  if ( (rc != 0) || (!S_ISDIR(statbuf.st_mode)) ) {
    return false;
  }

  // If this was a root directory strip the trailing delimiter.
  if ( c[3] == 0 ) {
    c[2] = 0;
  }

  strupr( c );
  strcpy( path, c );

  return true;

}



static char CopyrightMsg1[] = "mTCP HttpServ by M Brutman (mbbrutman@gmail.com) (C)opyright 2013-2026\n";
static char CopyrightMsg2[] = "Version: " __DATE__ "\n\n";

// init
//
// Do all of the one-time setup steps in this routine so that any stack
// space that is required does not persist for the entire length of the
// program.
//
// This parses command line arguments, reads configuration options and checks
// for obvious errors before getting started.  Use stdout and stderr
// until we are past the obvious errors.

void init( int argc, char *argv[] ) {

  printf( "%s %s", CopyrightMsg1, CopyrightMsg2 );


  // Sleazy hack to get tracing started earlier than usual.  Most programs
  // wait for Utils::initStack to do it, but we need it earlier for malloc
  // tracing.
  #ifndef NOTRACE
  Trace_LogFile = getenv( "LOGFILE" );
  Trace_beginTracing( );
  #endif


  // Errors in parseArgs will show the command line help and exit directly.
  parseArgs( argc, argv );

  if ( (Utils::parseEnv( ) != 0) || (getCfgOpts( ) != 0) ) {
    exit( 1 );
  }


  if ( !isPathValidForServing( HTTPDocs ) ) {
    fprintf( stderr, DocRootMsgTemplate, "doc root", HTTPDocs );
    exit( 1 );
  }


  if ( Client::initClients( MaxClients ) != 0 ) {
    fprintf( stderr, "Not enough memory to create %u clients.\n", MaxClients );
    exit( 1 );
  }

  if ( TreeNode::init( DirCacheSize, HTTPDocs ) != 0 ) {
    fprintf( stderr, "Error initializing directory cache\n" );
    exit( 1 );
  }

  if ( readRealms( ) != 0 ) {
    fprintf( stderr, "Error opening HTTPSERV_REALMS file.\n" );
    exit( 1 );
  }

  if ( LogFilename[0] ) {

    LogFileBuffer = (char *)mTCP_malloc(LOGFILE_BUFFER_SIZE, "HTTP_LogBuffer");
    if ( LogFileBuffer == NULL ) {
      fprintf( stderr, "Can not create log file buffer.\n" );
      exit( 1 );
    }

    LogFileBufferBytes = 0;

    LogFile = fopen( LogFilename, "ac" );
    if ( LogFile == NULL ) {
      fprintf( stderr, "Can not open log file for writing.\n" );
      exit( 1 );
    }
  }


  // If the server name was not set then set it now.
  if ( *ServerName == 0 ) {
    sprintf( ServerName, "%u.%u.%u.%u:%u", MyIpAddr[0], MyIpAddr[1], MyIpAddr[2], MyIpAddr[3], LclPort );
  }


  // Initialize TCP/IP

  if ( Utils::initStack( MaxClients + 8, TCP_MAX_XMIT_BUFS, ctrlBreakHandler, ctrlBreakHandler ) ) {
    fprintf( stderr, "Failed to initialize TCP/IP\n" );
    exit(1);
  }

  // From this point forward you have to call Utils::endStack( ) routine to
  // exit because we have the timer interrupt hooked.


  #ifdef SNTP_CLIENT
  // If SNTP is enabled resolve the host name and initialize the SNTP library.

  if ( *SNTPServerName ) {
    // Resolve the name and definitely send the request
    int8_t rc = Dns::resolve( SNTPServerName, SNTPServerAddr, 1 );
    if ( rc < 0 ) {
      fprintf( stderr, "Error resolving SNTP server.\n" );
      Utils::endStack( );
      exit( -1 );
    }

    while ( 1 ) {
      if ( CtrlBreakDetected ) shutdown(-1);
      if ( !Dns::isQueryPending( ) ) break;
      Utils::processPackets( );
      Dns::drivePendingQuery( );
    }

    // Query is no longer pending.  Did we get an answer?
    if ( Dns::resolve( SNTPServerName, SNTPServerAddr, 0 ) != 0 ) {
      fprintf( stderr, "Error resolving SNTP server.\n" );
      Utils::endStack( );
      exit( -1 );
    }

    SntpLib::init( SNTPServerAddr, 123, sntpClient );
  }
  #endif


  if ( initScreen( ) != 0 ) {
    fprintf( stderr, "Error allocating memory for screen messages.\n" );
    Utils::endStack( );
    exit( -1 );
  }


  // From this point forward you should call shutdown( ) routine to
  // exit because the screen is initialized.  shutdown( ) will call
  // Utils::endStack( ) and flush the logs.

  detectMachineDetails( );

  addToScreen( MSG_NORM, "%s  %s", CopyrightMsg1, CopyrightMsg2 );

  addToScreen( MSG_NORM, "Server name: %s, Clients: %u\n", ServerName, MaxClients );
  addToScreen( MSG_NORM, "Directories and logs:\n  HTTPDocs: %s\n  HTTPZips: %s\n  Log file: %s\n",
                         HTTPDocs,
                         (*HTTPZips == 0 ? "Not used" : HTTPZips),
                         (LogFile == NULL ? "NOT LOGGING" : LogFilename) );
  addToScreen( MSG_NORM, "Allow directory listings: %s\n", (DirectoryIndexingAllowedDefault ? "yes" : "no" ) );
  addToScreen( MSG_NORM, "Directory cache: %uKB, Free memory: %luKB\n", (DirCacheSize/1024), (getFreeDOSMemory( )/64ul) );

  #ifdef SNTP_CLIENT
  if ( !Ip::isSame( SNTPServerAddr, IpInvalid ) ) {
    addToScreen( MSG_NORM, "Syncing time with %s\n", SNTPServerName );
  }
  #endif

  if ( !Ip::isSame( UDP_target_addr, IpInvalid ) ) {
    addToScreen( MSG_NORM, "UDP logging target: %d.%d.%d.%d:%d\n",
                 UDP_target_addr[0], UDP_target_addr[1], UDP_target_addr[2], UDP_target_addr[3], UDP_target_port );
  }

  if ( Shutdown_Hour != -1 ) {
    addToScreen( MSG_NORM, "Scheduled shutdown at %02d:%02d\n", Shutdown_Hour, Shutdown_Minute );
  }


  addToScreen( MSG_NORM, "Waiting for a connection on port %u. Press [ALT-X] to abort.\n\n", LclPort );

  // Add free memory here.

  StartTime = time( NULL );
  _ctime( &StartTime, StartTimeString );
  StartTimeString[24] = 0;

}



// Declare the timers as globals to be safe.  They are going to be updated
// under the timing interrupt so using stack variables introduces risk.
static uint16_t idleMaintTimer, udpStatusTimer, timeoutSweepTimer, localServiceTimer, sntpUpdateTimer;

int main( int argc, char *argv[] ) {

  init( argc, argv );

  TcpSocket *listeningSocket = TcpSocketMgr::getSocket( );
  #ifdef HTTPSRV_CONSISTENCY_CHECK
  assert( listeningSocket != NULL );
  #endif

  listeningSocket->listen( LclPort, CLIENT_TCP_BUFFER_SIZE );


  // Initialize timers

  Timer_SetCountdownTimerSecs( idleMaintTimer, 5 );
  Timer_manageTimer( &idleMaintTimer );

  Timer_SetCountdownTimerMins( udpStatusTimer, 5 );
  Timer_manageTimer( &udpStatusTimer );

  Timer_SetCountdownTimerMs( timeoutSweepTimer, 500 );
  Timer_manageTimer( &timeoutSweepTimer );

  Timer_SetCountdownTimerMs( localServiceTimer, 500 );
  Timer_manageTimer( &localServiceTimer );

  #ifdef SNTP_CLIENT
  Timer_SetCountdownTimerMins( sntpUpdateTimer, 10 );
  Timer_manageTimer( &sntpUpdateTimer );
  #endif


  // When true we'll accept new TCP sockets but not process them.  Useful for
  // temporarily holding off new clients while we do maintenance.
  bool holdNewConnections = false;

  while ( Shutdown < 2 ) {

    PACKET_PROCESS_MULT( 4 );
    Arp::driveArp( );
    Tcp::drivePackets( );

    #ifdef HTTPSRV_CONSISTENCY_CHECK
    assert( _heapchk( ) == _HEAPOK );
    #endif


    // Things to do when we are idle for five seconds.

    if ( (Client::getActiveCount( ) == 0) && (Timer_isExpired( idleMaintTimer )) ) {

      Timer_SetCountdownTimerSecs( idleMaintTimer, 5 );

      flushLogs( );

      // See if somebody wants the file cache flushed.  This usually never
      // happens but this is the safe place to do it and the check is
      // lightweight.
      if ( FileCache::isCacheClearRequested( ) ) FileCache::clearCache( );

      // Same thing for the dir cache; if a flush was requested then do it.
      if ( TreeNode::isCacheFlushRequested( ) ) TreeNode::flushCache( );


      // Shutdown time check.
      //
      // We need to have been running for at least 2 minutes before shutting down.
      // This keeps us from tripping ourselves and trying to shutdown immediately
      // after starting.

      if ( Shutdown_Hour != -1 ) {
        if ( (time( NULL ) - StartTime) > 120 ) {
          struct dostime_t t;
          _dos_gettime( &t );
          if ( (Shutdown_Hour == t.hour) && (Shutdown_Minute == t.minute) ) {
            Shutdown = 2;
            Shutdown_Hour = -1;  // No point in checking again.
            addToScreen( MSG_NORM, "Predetermined shutdown time reached.\n" );
          }
        }
      }


      // Send a UDP status message every 5 minutes.
      if ( !Ip::isSame( UDP_target_addr, IpInvalid ) ) {
        if ( Timer_isExpired( udpStatusTimer ) ) {
          Timer_SetCountdownTimerMins( udpStatusTimer, 5 );
          sendStatusUDP( );
        }
      }


      #ifdef SNTP_CLIENT
      // Send an Sntp request every 10 minutes.
      if ( Timer_isExpired(sntpUpdateTimer) ) {

        Timer_SetCountdownTimerMins( sntpUpdateTimer, 10 );

        // If the IP address is invalid check to see if we are waiting on DNS.
        // If we are not, then check to see if we got a response, and if we
        // did not get a response then fire off a new DNS query.

        if ( Ip::isSame( SNTPServerAddr, IpInvalid ) ) {
          if ( !Dns::isQueryPending( ) ) {
            if (Dns::resolve( SNTPServerName, SNTPServerAddr, 0 ) != 0 ) {
              Dns::resolve( SNTPServerName, SNTPServerAddr, 1 );
            }
          }
        }


        // We have an IP address for the server.
        if ( !Ip::isSame( SNTPServerAddr, IpInvalid ) ) {

          // Fire off a request but don't wait for it.
          uint32_t bogus1, bogus2;
          SntpLib::sendSNTPRequest( false, &bogus1, &bogus2 );
          addToScreen( MSG_NORM, "Syncing time via SNTP\n" );

          // After 10 times refresh the DNS address.
          SntpRequestCounter++;
          if ( SntpRequestCounter > 9 ) {

            SntpRequestCounter = 0;

            // Remove the entry from DNS and wipe our saved address.
            Dns::deleteFromCache( SNTPServerName );
            Ip::copy( SNTPServerAddr, IpInvalid );

            // No need to check the return code this time.
            Dns::resolve( SNTPServerName, SNTPServerAddr, 1 );

            addToScreen( MSG_NORM, "Confirming SNTP server address\n" );
          } 

        }

      }
      #endif

    } // Five second maintenance tasks.


    // Things to do once or twice a second, even if we are not idle.
    //
    // - Check for Ctrl-Break or Ctrl-C
    // - Read keyboard input
    // - Redraw the status line
    // - Update the logs area of the screen

    if ( Timer_isExpired( localServiceTimer ) ) {

      Timer_SetCountdownTimerMs( localServiceTimer, 500 );

      ActiveClients = Client::getActiveCount( );
      redrawStatusLine( );
      paintScreenIfNeeded( );

      #ifdef SNTP_CLIENT
      Dns::drivePendingQuery( );
      #endif

      if ( CtrlBreakDetected ) Shutdown = 2;

      if ( biosIsKeyReady( ) ) {

        uint16_t key = biosKeyRead( );
        char ch = key & 0xff;

        if ( ch == 0 ) {

          uint8_t ekey = key >> 8;

          // Pressed shutdown once already, but did not press it again.
          // So they did not mean it.
          if ( (Shutdown == 1) && (ekey != 45) ) Shutdown = 0;

          if ( ekey == 35 ) { // Alt-H
            addToScreen( (MSG_NORM|MSG_FLAG_NOLOG|MSG_FLAG_NO_TS),
                          "\nmTCP HTTPServ (" __DATE__ ")\n\n"
                          "Commands: Alt-B: Beep Toggle   Alt-L: Toggle logging   Alt-V: Verbosity Level\n"
                          "          Alt-X: Shutdown"
                       );
          }

          else if ( ekey == 45 ) { // Alt-X
            Shutdown++;
            if ( Shutdown > 2 ) Shutdown = 2;
            if ( Shutdown == 1 ) {
              addToScreen( MSG_NORM, "Press Alt-X one more time to shut down or another key to cancel\n" );
            } else if ( Shutdown == 2 ) {
              addToScreen( MSG_NORM, "Shutdown started\n" );
            }
          }

          else if ( ekey == 47 ) { // Alt-V
            Verbosity++;
            if ( Verbosity > 3 ) Verbosity = 1;
            sound(500); delay(50); sound(750); delay(50); nosound( );
          }

          else if ( ekey == 48 ) { // Alt-B
            BeepToggle = !BeepToggle;
            if ( BeepToggle ) {
              sound(500); delay(50); sound(750); delay(50); nosound( );
            } else {
              sound(500); delay(50); nosound( );
            }
          }

          else if ( ekey == 38 ) { // Alt-L
            LogFilePaused = !LogFilePaused;
            addToScreen( MSG_NORM, "Log file paused: %d\n", LogFilePaused );
          }

          #ifdef KEYBOARD_COMMANDS
          else if ( ekey == 31 ) { // Alt-S

            char *cmd = readKeyboardString( );

            if ( stricmp( cmd, "* clear caches" ) == 0 ) {

              // Clear the caches now if there are no active clients.  Otherwise set flags
              // and wait for the number of active clients to go to zero.  That is not great
              // because they might be looking at stale data but it should not hurt them.
              //
              // Do this before shelling to reclaim memory used by the file cache.
              // Do this after shelling to reload the initial root node of the dir cache.

              if ( Client::getActiveCount( ) == 0 ) {
                FileCache::clearCache( );
                TreeNode::flushCache( );
                addToScreen( (MSG_NORM), "File and dir caches cleared.\n" );
              } else {
                FileCache::setClearCache( );
                TreeNode::setCacheFlushRequested( );
                addToScreen( (MSG_NORM), "File and dir caches will be cleared when idle.\n" );
              }

            }

            else if ( stricmp( cmd, "* drain" ) == 0 ) {
              holdNewConnections = true;
              addToScreen( (MSG_NORM), "Pausing new connections\n" );
            }

            else if ( stricmp( cmd, "* undrain" ) == 0 ) {
              holdNewConnections = false;
              addToScreen( (MSG_NORM), "Unpausing new connections\n" );
            }

            else if ( *cmd ) {
              addToScreen( (MSG_NORM), "Interactive command: %s\n", cmd );
              _heapmin( );
              system( cmd );
              while ( !biosIsKeyReady( ) ) { };
              biosKeyRead( );
            }

            drawStaticArea( );
            paintScreen( );
            redrawStatusLine( );
          }
          #endif

        } else {
          // Non-extended keystroke
          Shutdown = 0;
        }

      }

    } // end tasks to do twice a second.



    // Sweep for timeouts on clients.
    //
    // If we are just sitting around waiting for a client to send another
    // request and there are other pending sockets waiting to be serviced
    // because no clients are available then close the client socket to give
    // somebody else a chance.
    //
    // A more troublesome timeout is when the client is supposed to be doing
    // something and it just goes away.  Clean those up too, but only after
    // a longer interval.
    //
    // Sweep once a second unless we have a backlog.  If we have a backlog
    // sweep more agressively.

    bool socketsWaiting = (TcpSocketMgr::getSocketsPendingAccept( )) && !Client::areClientsAvailable( );

    if ( Timer_isExpired( timeoutSweepTimer ) ) {

      if ( socketsWaiting ) {
        Timer_SetCountdownTimerMs( timeoutSweepTimer, 500 );
      } else {
        Timer_SetCountdownTimerSecs( timeoutSweepTimer, 1 );
      }

      for ( uint16_t i=0; i < Client::getActiveCount( ); i++ ) {

        Client *tmpClient = Client::getClient( i );

        if ( tmpClient->getState( ) != Client::Closing ) {

          clockTicks_t elapsedTime = Timer_diff( tmpClient->getSocket( )->lastActivity, TIMER_GET_CURRENT( ) );

          if ( tmpClient->getState( ) == Client::ReadRequest ) {

            if ( (socketsWaiting && (elapsedTime > TIMER_SECS_TO_TICKS(1))) || (elapsedTime > TIMER_SECS_TO_TICKS(10)) ) {

              addToScreen( MSG_DEBUG, "%s: Closing idle client\n", tmpClient->getRemoteHostName( ) );

              tmpClient->getSocket( )->flushRecv( );
              tmpClient->close( );

            }

          }
          else if ( elapsedTime > TIMER_SECS_TO_TICKS(10) ) {

            addToScreen( MSG_DEBUG, "%s: Unexpected socket timeout: closing %d\n",
                         tmpClient->getRemoteHostName( ), tmpClient->getState( ) );

            tmpClient->getSocket( )->flushRecv( );
            tmpClient->close( );

          }

        } // end if not closing

      } // end for

    } // end if time to sweep

  


    // Check for new incoming sockets.  If we have no clients available the
    // newly connected sockets will wait until one is available.  This helps
    // us keep memory low by queuing waiting clients.

    // If holdNewConnections is set then we'll allow clients to connect but
    // we won't add their socket to the client list, effectively holding them
    // in limbo until we set holdNewConnections to false.
    if ( Client::areClientsAvailable( ) && (holdNewConnections == false) ) {

      TcpSocket *tmpSocket = TcpSocketMgr::accept( );

      if ( tmpSocket != NULL ) {
        Client *newClient = Client::allocateNewClient( tmpSocket );
        addToScreen( MSG_DEBUG, "New connection from: %s\n", newClient->getRemoteHostName( ) );
        SessionCounter++;
      }

    }



    // Service clients

    for ( uint16_t i=0; i < Client::getActiveCount( ); i++ ) {

      Client *tmpClient = Client::getClient( i );

      if ( tmpClient->getState( ) == Client::Closing ) {

        tmpClient->getSocket( )->flushRecv( );

        if ( tmpClient->getSocket( )->isCloseDone( ) ) {

          addToScreen( MSG_DEBUG, "Client released: %s\n", tmpClient->getRemoteHostName( ) );

          Client::releaseClient( tmpClient );

          // Break the loop and start from scratch because we changed the
          // order of entries in the Client table
          break;

        }

      }

      else {

        if ( tmpClient->getSocket( )->isRemoteClosed( ) ) {

          addToScreen( MSG_DEBUG, "Client initiated close: %s\n", tmpClient->getRemoteHostName( ) );

          tmpClient->close( );
          tmpClient->getSocket( )->closeNonblocking( );

        }

        else {

          if ( tmpClient->getState( ) == Client::ReadRequest ) {
            readRequest( tmpClient );
          }
          else if ( tmpClient->getState( ) == Client::SendingFile ) {
            tmpClient->sendFile( );
          }
          else if ( tmpClient->getState( ) == Client::SendingCachedFile ) {
            tmpClient->sendFileFromCache( 0, NULL );
          }
          else if ( tmpClient->getState( ) == Client::SendingDirectory ) {
            tmpClient->sendDirectory( );
          }

          if ( tmpClient->getState( ) == Client::ReqDone ) {
            if ( (tmpClient->getCloseWhenDone( )) || (tmpClient->httpRequest.getHttpVersion( ) == Request::Http09) ) {
              tmpClient->close( );
            }
            else {
              tmpClient->httpRequest.reset( true );
              tmpClient->setState( Client::ReadRequest );
            }
          }
          else if ( (tmpClient->getState( ) == Client::SocketError) || (tmpClient->getState( ) == Client::ForceClose) ) {
            tmpClient->close( );
          }

        }

      }

    } // end for

  } // end while


  paintScreen( );

  listeningSocket->close( );

  forceAllClientsClosed( );

  TcpSocketMgr::freeSocket( listeningSocket );

  shutdown( 0 );

  return 0;
}


#ifdef KEYBOARD_COMMANDS
static char keyboardString[80];

char * readKeyboardString( void ) {

  // Make room at the bottom of the screen.
  scrollScreen( 1, 2, 0, ScreenRows-1, ScreenCols-1 );
  gotoxy(0, ScreenRows-1);
  puts( "Enter command below. Press a key after to resume." );
  gotoxy(0, ScreenRows-1);

  int len = 0;

  while ( 1 ) {

    if ( biosIsKeyReady( ) ) {

      uint16_t key = biosKeyRead( );
      char ch = key & 0xff;

      if ( ch != 0 ) {

        if ( ch == 13 ) {
          keyboardString[len] = 0;
          break;
        }
        else if ( ch == 8 ) {
          if ( len ) {
            len--;
            gotoxy(len, ScreenRows-1);
            putch( ' ' );
            gotoxy(len, ScreenRows-1);
          }
        }
        else if ( (ch > 31) && (ch < 127) ) {
          if ( len < 79 ) {
            keyboardString[len] = ch;
            gotoxy(len, ScreenRows-1);
            putch( ch );
            len++;
          }
        }

      }

    } // End if a key is waiting

  }

  scrollScreen( 1, 2, 0, ScreenRows-1, ScreenCols-1 );
  gotoxy(0, ScreenRows-1);

  return keyboardString;
}
#endif



// forceAllClientsClosed
//
// This is probably overkill, but we are going to close each of the open
// connections and wait for it to close (or for the close to timeout).
// This includes connections that were pending accept.

void forceAllClientsClosed( void ) {

  // Scoop up connections waiting for accept and close them.  We have to
  // use an array to track each one individually.

  TcpSocket *lateSockets[TCP_MAX_SOCKETS];
  uint16_t socketsAcceptedLate = 0;

  while ( 1 ) {

    PACKET_PROCESS_MULT( 4 );
    Arp::driveArp( );
    Tcp::drivePackets( );

    TcpSocket *tmpSocket = TcpSocketMgr::accept( );
    if ( tmpSocket != NULL ) {
      lateSockets[socketsAcceptedLate] = tmpSocket;          // Add to our local table
      lateSockets[socketsAcceptedLate]->flushRecv( );        // Wipe out anything they received
      lateSockets[socketsAcceptedLate]->closeNonblocking( ); // Close it
      socketsAcceptedLate++;
    }
    else {
      break;
    }

  }

  addToScreen( MSG_DEBUG,
               "Shutdown: Forcing %d clients closed, detected %d late sockets\n",
               Client::getActiveCount( ), socketsAcceptedLate );


  // Close active clients whether they like it or not.

  for ( uint16_t i=0; i < Client::getActiveCount( ); i++ ) {

    PACKET_PROCESS_MULT( 4 );
    Arp::driveArp( );
    Tcp::drivePackets( );

    Client *tmpClient = Client::getClient( i );
    if ( tmpClient->getState( ) != Client::Closing ) {
      tmpClient->getSocket( )->flushRecv( );
      tmpClient->getSocket( )->closeNonblocking( );
      tmpClient->close( );

      addToScreen( MSG_DEBUG, "%s: Closing active client:\n", tmpClient->getRemoteHostName( ) );
    }

  }


  // Now wait for all of the clients and late sockets to get to the closed state
  // This might take a few seconds if things timeout.

  uint16_t acceptedLateNowClosed = 0;

  while ( Client::getActiveCount( ) || (acceptedLateNowClosed != socketsAcceptedLate) ) {

    PACKET_PROCESS_MULT( 4 );
    Arp::driveArp( );
    Tcp::drivePackets( );

    for ( uint16_t i=0; i < Client::getActiveCount( ); i++ ) {
      Client *tmpClient = Client::getClient( i );
      if ( tmpClient->getSocket( )->isCloseDone( ) ) {
        Client::releaseClient( tmpClient );
      }
    }

    for ( uint16_t i=0; i < socketsAcceptedLate; i++ ) {
      if ( (lateSockets[i] != NULL) && (lateSockets[i]->isCloseDone( )) ) {
        TcpSocketMgr::freeSocket( lateSockets[i] );
        lateSockets[i] = NULL;
        acceptedLateNowClosed++;
      }
    }

  }

}




// readRequest
//
// The client is in ReadRequest state.  Keep reading bytes from the socket and
// parsing what we receive until we receive a full request.  Once the parsing
// indicates that the request is complete process it.

void readRequest( Client *target ) {

  int16_t rc = target->readRequestBytes( );

  if ( rc == -1 ) {
    // Socket read error
    addToScreen( MSG_DEBUG, "Client socket read error: %s\n", target->getRemoteHostName( ) );
    target->setState( Client::SocketError );
    return;
  }

  Request::ParseStatus parseRc = target->httpRequest.parse( target );

  switch ( parseRc ) {

    case Request::Incomplete: {
      // Nothing to do yet.
      break;
    }

    case Request::RequestOverflowed: {
      addToScreen( MSG_ERROR, "%s HTTP Request overflowed\n", target->getRemoteHostName( ) );
      target->sendHaiku( 400, true );
      break;
    }

    case Request::Complete: {

      if (BeepToggle) { sound(500); delay(20); nosound( ); }

      serveFileOrDirectory( target );


      addToScreen( MSG_NORM, "%s %s %s %s %d\n", 
                     target->getRemoteHostName( ),
                     target->getHttpMethodString( ),
                     target->httpRequest.getURIString( ),
                     target->getHttpVersionString( ),
                     target->httpRequest.getResponseCode( ) );


      for ( Request::HttpRequestStringNums i=Request::Host; i < Request::LastString; i = Request::HttpRequestStringNums(i+1) ) {
        if ( target->httpRequest.getGenericRequestValueString( i ) != NULL ) {
          addToScreen( (MSG_VERBOSE|MSG_FLAG_NO_TS), "  %s %s\n", Request::HttpRequestNames[i], target->httpRequest.getGenericRequestValueString( i ) );
        }
      }

      if ( *(target->httpRequest.getURIParmString( )) ) {
        addToScreen( (MSG_VERBOSE|MSG_FLAG_NO_TS), "  <URI parameters>: %s\n", target->httpRequest.getURIParmString( ) );
      }

      break;
    }

    case Request::UriTooLong: {
      target->httpRequest.setResponseCode( 414 );
      addToScreen( MSG_ERROR, "%s %s <URI TOO LONG> %s 414\n", 
                      target->getRemoteHostName( ),
                      target->getHttpMethodString( ),
                      target->getHttpVersionString( ) );
      target->sendHaiku( 414, true );
      break;
    }

    case Request::BadCharacters: {
      addToScreen( MSG_ERROR, "%s Invalid characters detected 400\n", target->getRemoteHostName( ) );
      target->sendHaiku( 400, true );
      break;
    }

    case Request::Blocked: {
      addToScreen( MSG_ERROR, "%s Blocked\n", target->getRemoteHostName( ) );
      break;
    }

    default: {
      addToScreen( MSG_ERROR, "%s Parse error on HTTP req 400\n", target->getRemoteHostName( ) );
      target->sendHaiku( 400, true );
      break;
    }

  } // end switch

}




// I really really want to be able to cache file stat information in a tree
// structure but that gets really complicated, really fast - especially if
// you run out of memory and want to continue gracefully.
//
// For the first pass implement the ability to map long names to DOS names
// based on a mapping file in each directory.  Cache those in a tree structure.
// That gives us a much needed function.
//
// Algorithm:
//
// - At startup create a root node for HTTPDOCS and read the htaccessfile
// 
// When you have to rewrite a path:
//
// - Traverse down the path one component at a time doing mappings
// - If you hit the end of the tree and still have a component left to
//   map then this is a new part of the file system.  Create nodes on
//   the tree and keep going.



// We could save a little storage by having one list of MIME descriptions and
// having each extension index into that array.  But if somebody goofs the
// order of the array everything will be broken.

typedef struct {
  char *extension;
  char *contentString;
} ContentMapRecord_t;


static const ContentMapRecord_t ContentMap[] = {

  { "pdf", "application/pdf" },
  { "zip", "application/zip" },
  { "gz",  "application/gzip" },

  { "jpg", "image/jpeg" },
  { "gif", "image/gif" },
  { "png", "image/png" },

  { "bat", "text/plain" },
  { "css", "text/css" },
  { "csv", "text/csv" },
  { "htm", "text/html" },
  { "js",  "text/javascript" },
  { "lst", "text/plain" },
  { "txt", "text/plain" },
  { "xml", "text/xml" },

  { "", "" }

};

static char FileDate_Buffer[64];



// serveFileOrDirectory
//
// At this point we have a request from the client and a URI string.
// The URI string might have components that are not valid for DOS.
// See if a mapping to a valid DOS name exists.

void serveFileOrDirectory( Client *target ) {

  static char tmpFullPath[DOS_MAX_PATHFILE_LENGTH];

  ObjectsServed++;

  Request::HttpVer httpVersion = target->httpRequest.getHttpVersion();


  // Create a string that is the full path.  That includes the document root.
  // (Note that the document root here is what was specified in HTTPDocs.)
  TreeNode::WalkStatus walkRc = TreeNode::walkPath( target->httpRequest.getURIString( ),
                                                    target->httpRequest.getAuthUser( ),
                                                    target->httpRequest.getAuthPass( ),
                                                    target->fullPath,
                                                    false );

  addToScreen( MSG_DEBUG, "%s WalkPath rc: %u RealPath: %s\n", target->getRemoteHostName( ), walkRc, target->fullPath );


  switch ( walkRc ) {

    case TreeNode::Directory: {
      // sendDirectory will close the connection.
      target->sendDirectory( );
      break;
    }

    case TreeNode::DirectoryRedir: {
      // Connection is left open if possible
      target->send301ForDirectory( );
      break;
    }

    case TreeNode::BadPath: {
      // send404Haiku will set the client state to ReqDone
      target->sendHaiku( 404, false );
      break;
    }

    case TreeNode::InternalError: {
      target->send500InternalError( );
      break;
    }

    case TreeNode::NeedsAuth: {
      target->send401NeedsAuth( TreeNode::tmpRealm );
      break;
    }

    case TreeNode::Forbidden: {
      // send404Haiku will set the client state to ReqDone
      target->sendHaiku( 403, false );
      break;
    }

    case TreeNode::GenStatusPage: {
      serveStatusPage( target );
      break;
    }

    case TreeNode::GenClientsPage: {
      serveClientsPage( target );
      break;
    }

    case TreeNode::GenCacheCmds: {
      FileCache::handleCommand( target );
      break;
    }

    case TreeNode::GenServerQuit: {
      Shutdown = 2;
      addToScreen( MSG_NORM, "Shutdown requested by http request\n" );
      break;
    }

  }


  // Only case left is PossibleFile, which is too big to put in the switch.

  if ( walkRc != TreeNode::PossibleFile ) return;



  bool     fileFound = false;
  uint32_t fileSize = 0;
  time_t   fileTime = 0;
  bool     gzippedContent = true;
  uint8_t *filePointer = NULL;


  // Check the cache to see if we can serve this content from the cache.
  // If the client can handle a compressed version search for that first.

  int8_t fileCacheRc = -1;

  if ( target->httpRequest.getGzipAccepted( ) && (*HTTPZips) ) {

    // Strip off the HTTPDocs prefix and put in the HTTPZips prefix instead.
    strcpy( tmpFullPath, HTTPZips );
    int skipLen = strlen( HTTPDocs );
    strcat( tmpFullPath, target->fullPath + skipLen );

    fileCacheRc = FileCache::searchCache( tmpFullPath );

  }

  // If fileCacheRc is -1 then the client could not handle a
  // compressed version or a compressed version does not exist.
  // Repeat the search except look for the non-compressed version.

  if ( fileCacheRc == -1 ) {
    gzippedContent = false;
    fileCacheRc = FileCache::searchCache( target->fullPath );
  }

  if ( fileCacheRc != -1 ) {

    fileFound = true;

    FileCache::cacheHits++;

    fileSize = FileCache::getEntry(fileCacheRc)->fileSize;
    fileTime = FileCache::getEntry(fileCacheRc)->fileTime;
    filePointer = FileCache::getEntry(fileCacheRc)->filePointer;

    addToScreen( MSG_DEBUG, "Cache hit: %s\n", FileCache::getEntry(fileCacheRc)->fileName );
  }

  else {

    // Not in the cache.  Stat the target to see if we can serve it.

    struct stat statbuf;
    int statRc;

    statRc = stat( target->fullPath, &statbuf );
    addToScreen( MSG_DEBUG, "Stat on file: %s  statRc: %d\n", target->fullPath, statRc );

    if ( (statRc == 0) && S_ISREG(statbuf.st_mode) ) {

      fileFound = true;
      fileSize = statbuf.st_size;
      fileTime = statbuf.st_mtime;
      gzippedContent = false;

      if ( target->httpRequest.getGzipAccepted( ) && (*HTTPZips)  ) {

        // If we have HTTPZIPS available then construct a parallel path to our
        // file and stat it to see if it exists.

        strcpy( tmpFullPath, HTTPZips );
        int skipLen = strlen( HTTPDocs );
        strcat( tmpFullPath, target->fullPath + skipLen );

        statRc = stat( tmpFullPath, &statbuf );
        addToScreen( MSG_DEBUG, "Gzip stat on file: %s  statRc: %d\n", tmpFullPath, statRc );

        if ( (statRc == 0) && (S_ISREG(statbuf.st_mode)) ) {

          // Great, use the gzipped version instead.  The user is responsible
          // for ensuring the file timestamps are the same.

          strcpy( target->fullPath, tmpFullPath );
          fileSize = statbuf.st_size;
          fileTime = statbuf.st_mtime;
          gzippedContent = true;

          addToScreen( MSG_DEBUG, "Gzipped version found\n" );

        }

      }

    }

  }


  if ( fileFound ) {

    // Send the headers and the file contents

    target->httpRequest.setResponseCode( 200 );

    if ( httpVersion > Request::Http09 ) {

      // Can we send a 304 instead?
      if ( fileTime <= target->httpRequest.getIfModifiedSinceTime( ) ) {

        target->httpRequest.setResponseCode( 304 );
        if( target->sendHeaders( 304, "Not Modified", false, false, false, false, 0, NULL,
                                 Client::Expires_DoNotSend, NULL, "send304" ) ) return;
        target->setState( Client::ReqDone );

        // early return; headers sent, not content left to send
        return;

      } else {

        target->formatInternetDate( FileDate_Buffer, 64, "Last-Modified", fileTime );


        // Set the content type based on the file extension.
        //
        // The while loop searches for the beginning of the file extension.  It
        // stops when it hits a path delimiter or a dot.  If you hit the path
        // delimiter there is no extension.  If you hit a dot there might be an
        // extension.  (Somebody might have give you a null extension, so be
        // careful.)

        const char *contentStr = "";

        int extStart = strlen( target->fullPath ) - 1;
        while ( (target->fullPath[extStart] != '/') && (target->fullPath[extStart] != '.') ) extStart--;

        if ( target->fullPath[extStart] == '.') {
          extStart++;
          for ( int i = 0; ContentMap[i].extension[0] != 0; i++ ) {
            if ( stricmp( target->fullPath + extStart, ContentMap[i].extension ) == 0 ) {
              contentStr = ContentMap[i].contentString;
              break;
            }
          }
        }

        if ( target->sendHeaders( 200, "OK", false, gzippedContent, false, false, fileSize, contentStr,
                                  Client::Expires_LongFuture, FileDate_Buffer, "ServeFile" ) ) return;

      }

    }

    if ( target->httpRequest.getHttpMethod( ) == Request::GET ) {

      if ( filePointer == NULL ) {
        target->sendFile( );
      }
      else {
        target->sendFileFromCache( fileSize, filePointer );
        FileCache::filesServed++;
      }

    }
    else {
      target->setState( Client::ReqDone );
    }

  } // end if is regular file

  else {

    // send404Haiku will set the client state to ReqDone
    target->sendHaiku( 404, false );

  }

}



void sendStatusUDP( void ) {

  time_t ltime;
  struct tm t;
  time( &ltime );
  _localtime( &ltime, &t );

  int bytes = snprintf( Udp_lp.payload, UDP_LOGGING_PAYLOAD,
      "%4d.%02d.%02d %02d:%02d:%02d Connections: %lu, Objects: %lu\n"
      "    TCP Packets: sent: %lu, recv: %lu, retrans: %lu, sequence errs: %lu, dropped: %lu\n"
      "    IP: ICMP: %lu, frags recv: %lu, chksum errs: %lu, unhandled prot: %lu\n"
      "    Packet: sent: %lu, recv: %lu, dropped: %lu, send errs: %lu, low buf count: %u\n" 
      "    HTTP: 200: %lu, 301: %lu, 304: %lu, 400: %lu, 401: %lu, 403: %lu, 404: %lu, 414: %lu, 500: %lu\n",
      t.tm_year+1900, t.tm_mon+1, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec,
      SessionCounter, ObjectsServed,
      Tcp::Packets_Sent, Tcp::Packets_Received,
      Tcp::Packets_Retransmitted, Tcp::Packets_SeqOrAckError, Tcp::Packets_DroppedNoSpace,
      Ip::icmpRecvPackets, Ip::fragsReceived, Ip::badChecksum, Ip::unhandledProtocol,
      Packets_sent, Packets_received, Packets_dropped, Packets_send_errs, Buffer_lowFreeCount,
      HTTP_RC_200, HTTP_RC_301, HTTP_RC_304, HTTP_RC_400, HTTP_RC_401,
      HTTP_RC_403, HTTP_RC_404, HTTP_RC_414, HTTP_RC_500
      );

  if ( bytes > UDP_LOGGING_PAYLOAD) bytes = UDP_LOGGING_PAYLOAD;
  if ( bytes > (MyMTU-28) ) bytes = (MyMTU-28);


  // We need to resolve ARP first before we can send this.
  // We are not going to be patient about it though.

  clockTicks_t startTime = TIMER_GET_CURRENT( );

  while ( 1 ) {

    int rc = Udp::sendUdp( UDP_target_addr, 2001, UDP_target_port, bytes, (uint8_t *)&Udp_lp, 1);

    // Exit if error or successful, stay if ARP resolution is needed.
    if ( rc < 1 ) break;

    if ( Timer_diff( startTime, TIMER_GET_CURRENT( ) ) > TIMER_MS_TO_TICKS( 200 ) ) {
      break;  // Giving up if ARP resolution doesn't happen quickly.
    }

    Utils::processPackets( );

  }


}


static const char *StatusPage_part1 = 
  "<html>"
    "<head>"
      "<title>mTCP HTTPServ Status Page</title>"
      "%s"
    "</head>"
    "<body>"
      "<h1>mTCP HTTPServ Status page</h1>"
      "<h2>Server Information</h2>"
      "<pre>"
      "Server build date: " __DATE__ "<br>"
      "Machine type:      %s<br>"
      "CPU type:          %s<br>"
      "DOS version:       %d.%02d<br>"
      "BIOS date:         %s<br>"
      "Server started:    %s<br>"
      "Current time:      %s<br>"
      "Elapsed time:      %02u:%02u:%02u<br>"
      "Dir cache size:    %u, Free: %u<br>"
      "Dir cache nodes:   %u<br>"
      "Dir cache flushes: %u<br>"
      "Files cached:      %u, Bytes: %lu<br>"
      "Free memory:       %lu<br>"
      "</pre>"
      "<h2>HTTP Stats</h2>"
      "<pre>"
      "Active connections: %8u<br>"
      "Total connections:  %8lu<br>"
      "Requests served:    %8lu<br>"
      "</pre>";

static const char *StatusPage_part2 = 
      "<h2>TCP Level Stats</h2>"
      "<pre>"
      "Packets sent:            %8lu<br>"
      "Packets received:        %8lu<br>"
      "Packets retransmitted:   %8lu<br>"
      "Sequence or ACK errors:  %8lu<br>"
      "Dropped (no space):      %8lu<br>"
      "</pre>"
      "<h2>IP Level Stats</h2>"
      "<pre>"
      "ICMP received:      %8lu<br>"
      "Fragments received: %8lu<br>"
      "Checksum errors:    %8lu<br>"
      "Unhandled protocol: %8lu<br>"
      "</pre>"
      "<h2>Packet driver Level Stats</h2>"
      "<pre>"
      "Packets sent:                    %8lu<br>"
      "Packets received:                %8lu<br>"
      "Packets dropped:                 %8lu<br>"
      "Packet send errors:              %8lu<br>"
      "Lowest number of rcv bufs avail: %8u<br>"
      "</pre>"
    "</body>"
  "</html>";



void serveStatusPage( Client *target ) {

  ObjectsServed++;

  target->httpRequest.setResponseCode( 200 );
  if ( target->httpRequest.getHttpVersion() > Request::Http09 ) {
    if( target->sendHeaders( 200, "OK", true, false, false, true, 0, "text/html",
                             Client::Expires_Immediate, NULL, "Status" ) ) return;
  }

  if ( target->httpRequest.getHttpMethod( ) == Request::HEAD ) {
    target->setState( Client::ReqDone );
    return;
  }

  // Use the client outputBuffer as our content buffer because it is relatively
  // large.  (Minimum 4KB.)  We are not going to check to ensure that the entire
  // status page fit.  If it does not the snprintf will protect us from corrupting
  // memory and the user will just see a truncated page, which is not desirable
  // but not fatal.

  char *outputBuffer = target->getOutputBuffer( );

  time_t currentTime = time( NULL );
  time_t diffTime =  currentTime - StartTime;
  uint16_t hours  = (diffTime/3600ul);
  uint16_t mins   = (diffTime/60ul) % 60;
  uint16_t secs   = diffTime % 60;

  char currentTimeString[26];
  _ctime( &currentTime, currentTimeString );
  currentTimeString[24] = 0;

  uint32_t availMem = getFreeDOSMemory( ) * 16ul;

  uint16_t contentBytes = snprintf( outputBuffer, CLIENT_OUTPUT_BUFFER_SIZE,
                                    StatusPage_part1,
                                    GA_Script,
                                    MachineTypeString, CPUTypeString, DOS_major, DOS_minor, BIOSDate,
                                    StartTimeString, currentTimeString, hours, mins, secs,
                                    DirCacheSize, TreeNode::cacheFree( ),
                                    TreeNode::getNodeCount( ), TreeNode::getCacheFlushes( ),
                                    FileCache::getFilesCached( ), FileCache::getTotalBytesCached( ),
                                    availMem,
                                    Client::getActiveCount( ),
                                    SessionCounter,
                                    ObjectsServed );

  if ( contentBytes > CLIENT_OUTPUT_BUFFER_SIZE ) {
    addToScreen( MSG_ERROR, "StatusPage: content overflowed.  Needed %u bytes\n", contentBytes );
    contentBytes = CLIENT_OUTPUT_BUFFER_SIZE;
  }
  else {

    // Did not overflow.  Add another chunk.

    contentBytes += snprintf( outputBuffer + contentBytes, (CLIENT_OUTPUT_BUFFER_SIZE - contentBytes),
                              StatusPage_part2,
                              Tcp::Packets_Sent, Tcp::Packets_Received,
                              Tcp::Packets_Retransmitted, Tcp::Packets_SeqOrAckError, Tcp::Packets_DroppedNoSpace,
                              Ip::icmpRecvPackets, Ip::fragsReceived, Ip::badChecksum, Ip::unhandledProtocol,
                              Packets_sent, Packets_received, Packets_dropped,
                              Packets_send_errs, Buffer_lowFreeCount );

    if ( contentBytes > CLIENT_OUTPUT_BUFFER_SIZE ) {
      addToScreen( MSG_ERROR, "StatusPage: content overflowed.  Needed %u bytes\n", contentBytes );
      contentBytes = CLIENT_OUTPUT_BUFFER_SIZE;
    }

  }

  if ( target->send( (uint8_t *)outputBuffer, contentBytes ) == -1 ) return;

  target->setState( Client::ReqDone );

}



static const char *ClientsPage_part1 = 
  "<html>"
    "<head>"
      "<title>"
        "mTCP HTTPServ Clients Page"
      "</title>"
      "%s"
    "</head>"
    "<body>"
      "<h1>mTCP HTTPServ Clients page</h1>"
      "<pre>";

static const char *ClientsPage_part2 = 
      "</pre>"
    "</body>"
  "</html>";

void serveClientsPage( Client *target ) {

  ObjectsServed++;

  target->httpRequest.setResponseCode( 200 );
  if ( target->httpRequest.getHttpVersion() > Request::Http09 ) {
    if( target->sendHeaders( 200, "OK", true, false, false, true, 0, "text/html",
                             Client::Expires_Immediate, NULL, "Status" ) ) return;
  }                          
  
  if ( target->httpRequest.getHttpMethod( ) == Request::HEAD ) {
    target->setState( Client::ReqDone );
    return;
  } 
  
  // Use the client outputBuffer as our content buffer because it is relatively
  // large.  (Minimum 4KB.)  We are not going to check to ensure that the entire
  // status page fit.  If it does not the snprintf will protect us from corrupting
  // memory and the user will just see a truncated page, which is not desirable
  // but not fatal. 
  
  char *outputBuffer = target->getOutputBuffer( );

  uint16_t contentBytes = snprintf( outputBuffer, CLIENT_OUTPUT_BUFFER_SIZE, ClientsPage_part1, GA_Script );

  for ( uint16_t i=0; i < Client::getActiveCount( ); i++ ) {

    Client *tmpClient = Client::getClient( i );

    contentBytes += snprintf( (outputBuffer+contentBytes), (CLIENT_OUTPUT_BUFFER_SIZE-contentBytes),
                    "%22s%20s%10s %s<br>",
                    tmpClient->getRemoteHostName( ), Client::States[tmpClient->getState( )],
                    tmpClient->getHttpVersionString( ),
                    tmpClient->httpRequest.getURIString( ) );

    if ( contentBytes > CLIENT_OUTPUT_BUFFER_SIZE ) {
      contentBytes = CLIENT_OUTPUT_BUFFER_SIZE;
      break;
    }

  }

  contentBytes += snprintf( (outputBuffer+contentBytes), (CLIENT_OUTPUT_BUFFER_SIZE-contentBytes), ClientsPage_part2 );

  if ( contentBytes > CLIENT_OUTPUT_BUFFER_SIZE ) {
    addToScreen( MSG_ERROR, "ClientPage: content overflowed.  Needed %u bytes\n", contentBytes );
    contentBytes = CLIENT_OUTPUT_BUFFER_SIZE;
  }

  if ( target->send( (uint8_t *)outputBuffer, contentBytes ) == -1 ) return;

  target->setState( Client::ReqDone );

}







const char *HelpText[] = {
  "httpserv [options]\n",
  "  -help                    Shows this help\n",
  "  -clients <n>             Number of concurrent clients to support\n",
  "  -dir_indexes             Enable generating directory lists by default\n",
  "  -doc_root <dir>          Use <dir> as the document root\n",
  "  -port <n>                Use port <n> for incoming requests\n",
  "  -shutdown_at <xx:xx>     Shutdown at the specified time (24 hour format)\n",
  "  -udp_logging <x.x.x.x:p> Send log messages to IP addr x.x.x.x and port p\n\n"
  "Options provided on the command line override the config file.\n",
  NULL
};


void usage( void ) {
  uint8_t i=0;
  while ( HelpText[i] != NULL ) {
    fprintf( stderr, HelpText[i] );
    i++;
  }
  exit( 1 );
}


void errorMsg( char *msg ) {
  fprintf( stderr, "Error: %s\n\n", msg );
  usage( );
}


void parseArgs( int argc, char *argv[] ) {

  int i=1;
  for ( ; i<argc; i++ ) {

    if ( (stricmp( argv[i], "-help" ) == 0) || (stricmp( argv[i], "-h" ) == 0) ) {
      usage( );
    }

    else if ( stricmp( argv[i], "-clients" ) == 0 ) {
      i++;
      if ( i == argc ) errorMsg( "Need to specify the number of clients" );
      MaxClients = atoi( argv[i] );
      if ( (MaxClients < 1) || (MaxClients > MAX_CLIENTS) ) errorMsg( "Bad number of clients" );
    }

    else if ( stricmp( argv[i], "-dir_indexes" ) == 0 ) {
      DirectoryIndexingAllowedDefault = true;
    }

    else if ( stricmp( argv[i], "-doc_root" ) == 0 ) {

      i++;
      if ( i == argc ) errorMsg( "Need to specify a directory with -doc_root" );

      // If they try to give us something rediculous we won't buffer
      // overflow and they won't get reasonable behavior either.
      strncpy( HTTPDocs, argv[i], DOS_MAX_PATH_LENGTH );
      HTTPDocs[ DOS_MAX_PATH_LENGTH - 1 ] = 0;

    }

    else if ( stricmp( argv[i], "-port" ) == 0 ) {
      i++;
      if ( i == argc ) errorMsg( "Need to specify a port number with -port" );
      LclPort = atoi( argv[i] );
      if ( LclPort == 0 ) errorMsg( "Bad port number" );
    }

    else if ( stricmp( argv[i], "-udp_logging" ) == 0 ) {
      i++;
      if ( i == argc ) errorMsg( "Need to specify a numerical IP address and port with -udp_logging" );
      uint16_t tmp0, tmp1, tmp2, tmp3, tmp4;
      int rc = sscanf( argv[i], "%d.%d.%d.%d:%d", &tmp0, &tmp1, &tmp2, &tmp3, &tmp4 );
      if ( rc != 5 ) errorMsg( "Invalid ipaddr:port for -udp_logging" );
      UDP_target_addr[0] = tmp0; UDP_target_addr[1] = tmp1;
      UDP_target_addr[2] = tmp2; UDP_target_addr[3] = tmp3;
      UDP_target_port = tmp4;
    }

    else if ( stricmp( argv[i], "-shutdown_at" ) == 0 ) {
      i++;
      if ( i == argc ) errorMsg( "Need to specify a shutdown time with -shutdown_at" );
      uint16_t tmp0, tmp1;
      int rc = sscanf( argv[i], "%d:%d", &tmp0, &tmp1 );
      if ( (rc != 2) || (tmp0 < 0) || (tmp0 > 23) || (tmp1 < 0) || (tmp1 > 59) ) {
        errorMsg( "Invalid time format for -shutdown_at" );
      }
      Shutdown_Hour = tmp0;
      Shutdown_Minute = tmp1;
    }


    else {
      errorMsg( "Unknown command line option\n" );
    }

  }

}




int8_t getCfgOpts( void ) {

  char tmp[10];

  puts( "Reading HTTPserv configuration file options\n" );

  Utils::openCfgFile( );


  // Was a log file specified?
  Utils::getAppValue( "HTTPSERV_LOG_FILE", LogFilename, DOS_MAX_PATHFILE_LENGTH );


  // Read a server name if available.  If not it will be a null string and we will
  // fix it later, after LclPort is also known.
  Utils::getAppValue( "HTTPSERV_SERVERNAME", ServerName, SERVER_NAME_SIZE );


  // HTTPDOCS is required if it was not set on the command line.

  if ( *HTTPDocs == 0 ) {
    if ( Utils::getAppValue( "HTTPSERV_HTTPDOCS", HTTPDocs, DOS_MAX_PATH_LENGTH ) != 0 ) {
      fprintf( stderr, "Error: You must set HTTPSERV_HTTPDOCS\n" );
    }

    // HTTPZIPS is not required.  And it is only valid if it is set in the config
    // file with HTTPDocs.

    if ( Utils::getAppValue( "HTTPSERV_HTTPZIPS", HTTPZips, DOS_MAX_PATH_LENGTH ) == 0 ) {
      if ( !isPathValidForServing( HTTPZips ) ) {
        fprintf( stderr, DocRootMsgTemplate, "zips root", HTTPZips );
        return -1;
      }
    }

  }

  if ( Utils::getAppValue( "HTTPSERV_REALMS", RealmsFilename, DOS_MAX_PATHFILE_LENGTH ) == 0 ) {
    // No need to check it here - we will try to read it shortly.
  }


  // Verbosity level
  if ( Utils::getAppValue( "HTTPSERV_VERBOSITY", tmp, 10 ) == 0 ) {
    if ( stricmp( tmp, "low" ) == 0 ) {
      Verbosity = 1;
    } else if ( stricmp( tmp, "medium" ) == 0 ) {
      Verbosity = 2;
    } else if ( stricmp( tmp, "high" ) == 0 ) {
      Verbosity = 3;
    } else {
      fprintf( stderr, "Error: Bad HTTPSERV_VERBOSITY value: %s\n", tmp );
      return -1;
    }
  }

  // DirectoryIndexingAllowedDefault
  //
  // The default is false.  If the user provided an override on the command
  // line then do not read the configuration file value.

  if ( (DirectoryIndexingAllowedDefault == false) && (Utils::getAppValue( "HTTPSERV_DIR_INDEXES", tmp, 10 ) == 0) ) {
    if ( stricmp( tmp, "yes" ) == 0 ) {
      DirectoryIndexingAllowedDefault = true;
    } else if ( stricmp( tmp, "no" ) == 0 ) {
      DirectoryIndexingAllowedDefault = false;
    } else {
      fprintf( stderr, "Error: Bad HTTPSERV_DIR_INDEXES value: %s\n", tmp );
      return -1;
    }
  }


  // LclPort
  //
  // The default is 80 but we start at 0.  That allows us to detect if the user
  // set it on the command line, which we would treat as an override.

  if ( (LclPort == 0) && (Utils::getAppValue( "HTTPSERV_PORT", tmp, 10 ) == 0) ) {
    LclPort = atoi( tmp );
    if ( LclPort == 0 ) {
      fprintf( stderr, "Error: Bad HTTPSERV_PORT value: %d\n", LclPort );
      return -1;
    }
  }

  // If it was not set on the command line or in the config file then set it.
  if ( LclPort == 0 ) LclPort = 80;


  // Clients
  //
  // The default is 8 but we start at 0.  That allows us to detect if the user
  // set it on the command linen, which we would treat as an override.

  if ( (MaxClients == 0) && (Utils::getAppValue( "HTTPSERV_CLIENTS", tmp, 10 ) == 0) ) {
    MaxClients = atoi( tmp );
    if ( MaxClients == 0 || MaxClients > MAX_CLIENTS ) {
      fprintf( stderr, "Error: Bad HTTPSERV_CLIENTS value: %d\n", MaxClients );
      return -1;
    }
  }

  // If it was not set on the command line or in the config file then set it.
  if ( MaxClients == 0 ) MaxClients = MAX_CLIENTS;



  // Directory cache size
  if ( Utils::getAppValue( "HTTPSERV_DIR_CACHE", tmp, 10 ) == 0 ) {
    DirCacheSize = atoi( tmp );
    if ( (DirCacheSize < 4) || (DirCacheSize > 63) ) {
      fprintf( stderr, "Error: Bad HTTPSERV_DIR_CACHE value: %d\n", DirCacheSize );
      return -1;
    }
    DirCacheSize = DirCacheSize * 1024;
  }


  // Long term expiration time
  if ( Utils::getAppValue( "HTTPSERV_LONG_EXPIRE_HOURS", tmp, 10 ) == 0 ) {
    Content_Long_Expires_Time = atol( tmp );
    if ( (Content_Long_Expires_Time == 0) || (Content_Long_Expires_Time > 4320) ) {
      fprintf( stderr, "Error: Bad HTTPSERV_LONG_EXPIRE_HOURS value: %lu\n", Content_Long_Expires_Time );
      return -1;
    }
    Content_Long_Expires_Time = Content_Long_Expires_Time * 3600ul;
  }



  char tmpFilename[DOS_MAX_PATHFILE_LENGTH];

  if ( Utils::getAppValue( "HTTPSERV_GA_SCRIPT_FILE", tmpFilename, DOS_MAX_PATHFILE_LENGTH ) == 0 ) {

    FILE *f = fopen( tmpFilename, "r" );
    if ( f == NULL ) {
      fprintf( stderr, "Error: GA script filename is invalid.\n" );
      return -1;
    }

    // Figure out how many bytes to malloc

    int16_t bytesNeeded = 1; // Reserve for NULL.
    while ( !feof(f) ) {
      if ( fgetc(f) != EOF) bytesNeeded++;
    }

    GA_Script = (char *)mTCP_malloc( bytesNeeded, "HTTP_GA_Script" );
    if ( GA_Script == NULL ) {
      fprintf( stderr, "Error: Failed to allocate memory for GA script.\n" );
      return -1;
    }

    fseek( f, 0, 0 );

    bytesNeeded = 0;
    while ( !feof(f) ) {
      int c = fgetc(f);
      if ( c != EOF ) {
        GA_Script[bytesNeeded++] = c;
      }
    }
    GA_Script[bytesNeeded]= 0;

    fclose(f);

  }

  #ifdef SNTP_CLIENT
  // Just read the value for now; there is no validation I want to do here.
  // If it is a bad value then DNS will fail later.
  Utils::getAppValue( "HTTPSERV_SNTP_SERVER", SNTPServerName, SERVER_NAME_SIZE );
  #endif

  return 0;
}
    







void shutdown( int rc ) {

  // Make sure we get the ending stats if we had paused logging.
  // (Has no effect if there was not a log file.)
  if ( LogFilePaused ) {
    LogFilePaused = false;
  }

  addToScreen( MSG_NORM, "Ending stats: %lu requests answered over %lu sessions\n"
               "  HTTP Return codes:\n"
               "    200: %6lu   301: %6lu   304: %6lu   400: %6lu   401: %6lu\n"
               "    403: %6lu   404: %6lu   414: %6lu   500: %6lu\n"
               "  File cache: Hits: %6lu    Files served from cache: %6lu\n",
               ObjectsServed, SessionCounter,
               HTTP_RC_200, HTTP_RC_301, HTTP_RC_304, HTTP_RC_400, HTTP_RC_401,
               HTTP_RC_403, HTTP_RC_404, HTTP_RC_414, HTTP_RC_500,
               FileCache::cacheHits, FileCache::filesServed );

  paintScreen( );

  // Scroll six more lines and position the cursor at the bottom of the current
  // output so that the stats get printed in the right spot.

  gotoxy( 0, ScreenRows-1 );

  if ( LogFile != NULL ) {
    flushLogs( );
    fclose( LogFile );
  }

  Utils::endStack( );
  exit( rc );
}




// A realm protects a directory and everything underneath it. There is only
// one basic auth header per request, so having having multiple levels of
// protection in a URI is not possible.
//
// The reals file format is as follows:
//
// "Realm name or desc" password user1 [user2] [user3] ...
//
// The first pass of the file is to figure out how much storage is needed.
// In the second pass of the file we actually create the in-memory data
// structure.

const char *RealmParseErr_FormatStr = "Parse error reading realms file at line %u: %s\n";

int16_t readRealms( void ) {

  // Normally I'd be nervous about putting too much on a local stack frame but
  // this function is called once at init so it is not a problem.

  char lineBuffer[256];
  char tmpRealm[ HTTP_AUTH_MAX_REALM_LEN + 1 ];
  char tmpPassword[ CLIENT_AUTH_MAX_PASSWORD_LEN + 1];


  if ( *RealmsFilename == 0 ) return 0;

  FILE *realmsFile = fopen( RealmsFilename, "r" );
  if ( realmsFile == NULL ) return -1;

  int16_t readRealmsRc = 0;

  uint8_t pass = 0;
  uint16_t currentLineNumber;

  uint16_t bytesRequired = 0;
  char *nextPos = NULL;

  while ( (pass < 2) && (readRealmsRc == 0) ) {

    // If we are at the beginning of the second pass then we know how much
    // memory needs to be allocated.

    if ( pass == 1 ) {
      if ( bytesRequired ) {
        RealmsMap = (char *)mTCP_malloc( bytesRequired + 1, "HTTP_RealmsMap" );
        if ( RealmsMap == NULL ) {
          fprintf( stderr, "Out of memory error reading realms file\n" );
          readRealmsRc = -1;
          break;
        }
        nextPos = RealmsMap;
      }
    }

    currentLineNumber = 0;

    while ( !feof(realmsFile) ) {

      currentLineNumber++;

      char *rc = fgets( lineBuffer, 256, realmsFile );
      if ( rc == NULL ) break;


      // fgets leaves the newline in the string if the buffer is big enough.
      // If the newline character can not be found then the line was too
      // long or not properly terminated.

      {
        char *index = lineBuffer;
        while (*index && (*index != '\n')) index++;

        if ( *index ) {
          *index = 0;    // Get rid of the trailing new line character.
        }
        else {
          fprintf( stderr, RealmParseErr_FormatStr, currentLineNumber, "line too long or missing CR/LF at the end" );
          readRealmsRc = -1;
          break;
        }
      }


      // Add one to the maximum field length to read so that we can detect
      // if they fit within the field or if they would have overflowed it.

      char *nextTokenPtr = Utils::getNextToken( lineBuffer, tmpRealm, (HTTP_AUTH_MAX_REALM_LEN + 1) );
      uint16_t realmLen = strlen(tmpRealm);

      nextTokenPtr = Utils::getNextToken( nextTokenPtr, tmpPassword, (CLIENT_AUTH_MAX_PASSWORD_LEN + 1) );
      uint16_t passwordLen = strlen(tmpPassword);

      if ( (realmLen == 0) || (passwordLen == 0) || (nextTokenPtr == NULL) ) {
        fprintf( stderr, RealmParseErr_FormatStr, currentLineNumber, "not enough fields" );
        readRealmsRc = -1;
        break;
      }

      if ( (realmLen == HTTP_AUTH_MAX_REALM_LEN) || (passwordLen == CLIENT_AUTH_MAX_PASSWORD_LEN) ) {
        fprintf( stderr, RealmParseErr_FormatStr, currentLineNumber, "realm name or password too long" );
        readRealmsRc = -1;
        break;
      }


      // Skip past any white space since we are not using getNextToken
      while ( (*nextTokenPtr == ' ') || (*nextTokenPtr == '\t') ) nextTokenPtr++;

      if ( *nextTokenPtr ) {

        // Note that it is possible that they left extra spaces between names.
        // We are not going to try to detect and flag that; just tolerate it
        // when it comes time to search.

        uint16_t usersLen = strlen( nextTokenPtr );

        if ( pass == 0 ) {
          bytesRequired += realmLen + passwordLen + usersLen + 3;
        }
        else {
          strcpy( nextPos, tmpRealm );
          nextPos += realmLen + 1;
          strcpy( nextPos, tmpPassword );
          nextPos += passwordLen + 1;
          strcpy( nextPos, nextTokenPtr );
          nextPos += usersLen + 1;
        }

      } else {
        // Missing users field
        fprintf( stderr, RealmParseErr_FormatStr, currentLineNumber, "users field is missing" );
        readRealmsRc = -1;
        break;
      }

    } // end while not feof

    fseek( realmsFile, 0, 0 );
    pass++;

  }

  fclose( realmsFile );

  if ( readRealmsRc == 0 ) {

    // This protects us against an empty file; if it was empty nextPos would
    // be NULL.  If we did read and parse things then we need a second null
    // character to terminate the list.

    if ( nextPos ) *nextPos = 0;

  }

  return readRealmsRc;
}



// This is a nasty little function.  Besides giving you a pointer to the
// password field in the realms file, the code that calls it also assumes
// that the user ID list is in memory directly after the null character
// that terminates the string.

char *getRealmPassword( const char *targetRealm ) {

  char *pos = RealmsMap;

  while ( *pos ) {

    uint16_t skip = strlen( pos ) + 1;

    if ( stricmp( pos, targetRealm ) == 0 ) {
      return pos + skip;       // Return the start of the password
    }
    else {
      pos += skip;             // Skip the realm name
      pos += strlen(pos) + 1;  // Skip the password
      pos += strlen(pos) + 1;  // Skip the list of user names
    }

  }

  return NULL;
}



