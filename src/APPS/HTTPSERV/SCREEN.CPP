/*

   mTCP HTTPServ Screen.cpp
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


   Description: Screen handling functions for the http server.

*/


#include <dos.h>
#include <errno.h>
#include <malloc.h>
#include <memory.h>
#include <stdarg.h>

#include "timer.h"
#include "trace.h"
#include "utils.h"
#include "packet.h"
#include "arp.h"
#include "udp.h"

#include "screen.h"
#include "httpserv.h"


// Variables shared (extern) (extern) (extern) (extern) (extern) (extern) (extern) (extern) (extern) with the main program.

int      ScreenCols = 0, ScreenRows = 0;  // Detected at startup
bool     ScreenNeedsPainting;             // Used by the paintScreenIfNeeded macro


// Locals

uint8_t   Screen_errorColor;



// Virtual screen buffer
//
// Scrolling the dispaly takes time on a slow machine and it can make things
// hurt performance.  To improve performance on slow machines we make all
// screen writes to a virtual buffer.  The virtual buffer is copied onto the
// real video buffer on demand, usually twice a second.  This allows us to
// minimize the performance hit from scrolling.
//
// If you use the BIOS_SCREEN_WRITES option you save some memory by not
// creating the virtual buffer, but all of your screen writes will happen
// in real-time through the BIOS.  On faster machines this is not a problem,
// but on older machines this is going to hurt.

// Locals used for managing the virtual screen buffer.

#ifndef BIOS_SCREEN_WRITES
uint16_t far *Screen_base, *Screen_msgArea;
uint16_t *VirtualBuffer, *VirtualBufferEnd;
uint16_t *VirtualBufferNextPos;
uint16_t *VirtualBufferScreenTop;
#endif


// Static messages

char InternalLoggingError[] = "<INTERNAL LOGGING ERROR>";


// Local function prototypes

static void near myCprintf( uint8_t x, uint8_t y, uint8_t attr, char *fmt, ... );



int8_t initScreen( void ) {

  unsigned char screenMode = *((unsigned char far *)MK_FP( 0x40, 0x49 ));

  if ( screenMode == 7 ) {
    // MDA
    #ifndef BIOS_SCREEN_WRITES
    Screen_base = (uint16_t far *)MK_FP( 0xb000, 0 );
    #endif
    Screen_errorColor = 0xF;
  }
  else {
    // CGA, EGA or VGA
    #ifndef BIOS_SCREEN_WRITES
    Screen_base = (uint16_t far *)MK_FP( 0xb800, 0 );
    #endif
    Screen_errorColor = 0x4;
  }

  // Call int 10, ah=12 for EGA/VGA config

  if ( getEgaMemSize( ) == 0x10 ) {
    // Failed.  Must be MDA or CGA
    ScreenCols = 80;
    ScreenRows = 25;
  }
  else {
    ScreenCols = *((unsigned char far *)MK_FP( 0x40, 0x4A ));
    ScreenRows = *((unsigned char far *)MK_FP( 0x40, 0x84 )) + 1;
  }


  #ifndef BIOS_SCREEN_WRITES

  // Setup the virtual screen buffer.  It has almost all of the screen;
  // we don't need the top two lines because they are relativel static
  // and get updated using a different mechanism.
  int wordsRequiredForBuffer = ScreenCols * (ScreenRows-2);

  VirtualBuffer = (uint16_t *)mTCP_malloc( wordsRequiredForBuffer*2, "HTTP_Screen" );
  if ( VirtualBuffer == NULL ) return -1;

  // Clear the buffer
  fillUsingWord( VirtualBuffer, (7<<8|32), wordsRequiredForBuffer );

  VirtualBufferEnd = VirtualBuffer + wordsRequiredForBuffer;

  // Setup the current top of screen and the next writing position to
  // be near the bottom of the screen.

  VirtualBufferScreenTop = VirtualBuffer;
  VirtualBufferNextPos = VirtualBuffer + wordsRequiredForBuffer - ScreenCols;

  Screen_msgArea = Screen_base + (ScreenCols * 2);

  #endif


  ScreenNeedsPainting = false;

  drawStaticArea( );

  return 0;

}



/*
          1         2         3         4         5         6         7
01234567890123456789012345678901234567890123456789012345678901234567890123456789
mTCP HTTPServ: Connects: 00000 Active: 00 Objs Served: 000000    Alt-H for Help
*/

void drawStaticArea( void ) {
  // Clear the screen.
  scrollScreen( 0, 0, 0, ScreenRows-1, ScreenCols-1 );

  // Draw status and separator lines
  myCprintf(  0, 0, 0x1F, "mTCP HTTPServ:" );
  myCprintf( 15, 0, 0x0F, "Connects:" );
  myCprintf( 32, 0, 0x0F, "Active:" );
  myCprintf( 43, 0, 0x0F, "Objs Served:" );
  myCprintf( 66, 0, 0x0F, "Alt-H for Help" );

  for ( int i=0; i < ScreenCols; i++ ) {
    writeChar( i, 1, 0xc4, 0x07 );
  }

  myCprintf( 17, 1, 0x7, "[ Verbose:   ]" );
}

void redrawStatusLine( void ) {

  myCprintf( 25, 0, 0x07, "%6ld", SessionCounter );
  myCprintf( 40, 0, 0x07, "%2d", ActiveClients );
  myCprintf( 56, 0, 0x07, "%6ld", ObjectsServed );

  if ( BeepToggle ) {
    myCprintf( 4, 1, 0x7, "[ Beep on ]\xC4" );
  } else {
    myCprintf( 4, 1, 0x7, "[ Beep off ]" );
  }

  myCprintf( 28, 1, 0x07, "%u", Verbosity );

}



// paintScreen
//
// Our usual case is that our virtual top of screen is pointing to somewhere
// into the middle of our virtual screen.  This requires two separate memcpys
// to paint the screen.

void paintScreen( void ) {

  // If we are forcing the use of BIOS screen writes then calls to this
  // function are pointless.  However, there are only two of them and they
  // happen at the end of the program so there is no point in compiling this
  // function out entirely.

  #ifndef BIOS_SCREEN_WRITES

  uint16_t copyWords = VirtualBufferEnd - VirtualBufferScreenTop;

  if ( copyWords ) memcpy( Screen_msgArea, VirtualBufferScreenTop, copyWords*2 );

  uint16_t remainingWords = VirtualBufferScreenTop - VirtualBuffer;

  if ( remainingWords ) memcpy( Screen_msgArea + copyWords, VirtualBuffer, remainingWords * 2 );

  ScreenNeedsPainting = false;

  #endif
}



// flushLogs_private
//
// The macros use this under the covers.  In this context flush means flush the
// in memory logs buffer; we do not need to do a C runtime flush which would
// take longer.  (Add that if you are crashing and need the log messages to
// be fully up to date.)
//
// Don't call this unless you know you have a log file and bytes to write.
// Not have a log file is fatal.  Not having bytes to write is just a waste of
// CPU cycles.  (If you have bytes to write then you have a log file.)

void flushLogs_private( void ) {

  uint16_t rc = fwrite( LogFileBuffer, 1, LogFileBufferBytes, LogFile );

  if ( rc != LogFileBufferBytes ) {
    int lclErrno = errno;
    addToScreen( MSG_ERROR, "Error writing to log file, errno: %d\n", lclErrno );
    Shutdown = 2;
  }

  LogFileBufferBytes = 0;

}



// UDP logging.  Copied from HTTPSERV.CPP because I'm too lazy to start
// a new header file.

typedef struct {
  UdpPacket_t udpHdr;                 // Space for Ethernet, IP and UDP headers
  char payload[UDP_LOGGING_PAYLOAD];  // Log message area
} UDP_log_packet_t;

// Storage reserved in HTTPSERV.CPP
extern UDP_log_packet_t Udp_lp;
extern IpAddr_t UDP_target_addr;
extern uint16_t UDP_target_port;



// Buffer space used for writing logs and updating the screen.  This buffer
// space is used by addToScreen and myCprintf so make sure that they do not
// call each other.

char logLineBuffer[LOGFILE_MAX_ENTRY_SIZE];

// Number of chars in the timestamp to skip when writing to disk logs
#define SCREEN_TIMESTAMP_CHARS (9)




// addToScreen
//
// addToScreen is the primary method of logging activity, writing both to the
// screen and the log file if active.  If the mTCP trace log is active the
// messages will go there too.

void addToScreen( uint8_t flags, const char *fmt, ... ) {

  // Generally, if the message is to be logged and the log is open then write
  // the message.  This applies even if the user has the lowest level of
  // verbosity set; the log still gets everything even if it is not displayed
  // on the screen.  DEBUG messages are the exception; we don't log those
  // unless the user is actively looking at them.  It would create a lot of
  // noise in the log if we did.

  // Shortcut for DEBUG messages; if the user isn't looking at them then we
  // don't display them or log them.

  if ( ((flags & 0x3) == MSG_DEBUG) && (Verbosity < MSG_DEBUG) ) return;


  int bytesOut = 0;

  DosTime_t currentTime;
  DosDate_t currentDate;

  if ( !(flags & MSG_FLAG_NO_TS) ) {
    gettime( &currentTime );
    getdate( &currentDate );
    bytesOut = sprintf( logLineBuffer, "%02u:%02u:%02u ", currentTime.hour, currentTime.minute, currentTime.second );
  }

  // Remember where the text of the user message starts.
  int16_t userMsgStartPos = bytesOut;

  va_list ap;
  va_start( ap, fmt );
  bytesOut += vsnprintf( logLineBuffer+bytesOut, (LOGFILE_MAX_ENTRY_SIZE-bytesOut), fmt, ap );
  va_end( ap );

  if ( bytesOut > (LOGFILE_MAX_ENTRY_SIZE-1) ) {
    // Truncated output - better than nothing
    logLineBuffer[LOGFILE_MAX_ENTRY_SIZE-1] = 0;
    bytesOut = (LOGFILE_MAX_ENTRY_SIZE-1);
  }
  else if ( bytesOut < 0 ) {
    // Internal error - find and fix this!
    strcpy( logLineBuffer, InternalLoggingError );
    bytesOut = sizeof(InternalLoggingError) - 1;
  }

  // Send UDP packet if desired.
  if ( !Ip::isSame( UDP_target_addr, IpInvalid ) ) {

    int copyLen = bytesOut;
    if (copyLen > UDP_LOGGING_PAYLOAD) {copyLen = UDP_LOGGING_PAYLOAD; }
    if (copyLen > (MyMTU - 28)) { copyLen = MyMTU - 28; }
    memcpy( Udp_lp.payload, logLineBuffer, copyLen );

    // We need to resolve ARP first before we can send this.
    // We are not going to be patient about it though.

    clockTicks_t startTime = TIMER_GET_CURRENT( );

    while ( 1 ) {

      int rc = Udp::sendUdp( UDP_target_addr, 2001, UDP_target_port, copyLen, (uint8_t *)&Udp_lp, 1);

      // Exit if error or successful, stay if ARP resolution is needed.
      if ( rc < 1 ) break;

      if ( Timer_diff( startTime, TIMER_GET_CURRENT( ) ) > TIMER_MS_TO_TICKS( 200 ) ) {
        break;  // Giving up if ARP resolution doesn't happen quickly.
      }

      Utils::processPackets( );

    }

  }


  if ( !(flags & MSG_FLAG_NOLOG) ) {

    if ( (LogFile != NULL) && (!LogFilePaused) ) {

      int rc;

      if ( !(flags & MSG_FLAG_NO_TS) ) {

        // This timestamp includes the date too.

        rc = sprintf( (LogFileBuffer + LogFileBufferBytes),
                       "%04d-%02d-%02d %02d:%02d:%02d.%02d ",
                        currentDate.year, currentDate.month, currentDate.day,
                        currentTime.hour, currentTime.minute, currentTime.second,
                        currentTime.hsecond );

        LogFileBufferBytes += rc;

      }

      rc = sprintf( (LogFileBuffer + LogFileBufferBytes), "%s", (logLineBuffer + userMsgStartPos) );
      LogFileBufferBytes += rc;

      flushLogsIfNeeded( );

      // This is good when debugging but it can crush performance.
      #ifdef HTTPSRV_CONSISTENCY_CHECK
      flushLogs_private( );
      fflush( LogFile );
      #endif

    }

    // Add to mTCP log (if it is active).
    TRACE(( "Http %s", logLineBuffer + userMsgStartPos ));


  }


  if ( (flags & 0x3) > Verbosity ) return;


  // Figure out the screen attr to use.  Things that do not
  // go to the logfile get highlighted.  Errors have higher
  // priority than highlighting.

  uint16_t attr = 0x7;

  if ( flags & MSG_FLAG_NOLOG ) attr = 0xF;
  if ( (flags & 0x3) == MSG_ERROR ) attr = Screen_errorColor;


  #ifndef BIOS_SCREEN_WRITES

  // Now write the virtual buffer.  This assumes that we always start
  // at column 0 on the screen.

  attr = attr << 8;

  int x = 0;
  for ( uint16_t i = 0; i < bytesOut; i++ ) {

    if ( logLineBuffer[i] == 10 ) {
      VirtualBufferNextPos += (ScreenCols-x);
      x = 0;
    }
    else {
      *VirtualBufferNextPos++ = ( attr | logLineBuffer[i] );
      x++;
      if ( x == ScreenCols ) x = 0;
    }

    if ( x == 0 ) {
      if ( VirtualBufferNextPos >= VirtualBufferEnd ) VirtualBufferNextPos = VirtualBuffer;

      VirtualBufferScreenTop += ScreenCols;
      if ( VirtualBufferScreenTop >= VirtualBufferEnd ) VirtualBufferScreenTop = VirtualBuffer;

      fillUsingWord( VirtualBufferNextPos, (7<<8|32), ScreenCols );
    }

  }


  // If the user did not terminate with a new line we are going to help them.

  if ( x ) {
    VirtualBufferNextPos += (ScreenCols-x);
    if ( VirtualBufferNextPos >= VirtualBufferEnd ) VirtualBufferNextPos = VirtualBuffer;
    VirtualBufferScreenTop += ScreenCols;
    if ( VirtualBufferScreenTop >= VirtualBufferEnd ) VirtualBufferScreenTop = VirtualBuffer;
    fillUsingWord( VirtualBufferNextPos, (7<<8|32), ScreenCols );
  }


  ScreenNeedsPainting = true;

  #else

  // We are not using the virtual buffer to speed things up.  This means
  // scrolling and every char written go through the BIOS.

  // To minimize the scrolling pain, scan the output and figure out how
  // many lines we need to scroll to make room for this message.

  uint8_t lines = 0, x = 0;
  for (uint16_t i = 0; i < bytesOut; i++ ) {
    if ( logLineBuffer[i] == 10 ) {
      lines++;
      x = 0;
    } else {
      x++;
      if ( x == ScreenCols ) {
        x = 0;
        lines++;
      }
    }
  }
  if ( x ) lines++;  // If we left on a partial line, add a line.

  // Scroll the screen
  scrollScreen( lines, 2, 0, ScreenRows-1, ScreenCols-1 );


  // Write the characters
  uint8_t y = ScreenRows - lines;
  x = 0;
  for (uint16_t i = 0; i < bytesOut; i++ ) {
    if ( logLineBuffer[i] == 10 ) {
      y++;
      x = 0;
    } else {
      writeChar( x, y, logLineBuffer[i], attr );
      x++;
      if ( x == ScreenCols ) {
        x = 0;
        y++;
      }
    }
  }

  #endif
}




// This is not much of a cprintf - it doesn't handle new lines.  The primary
// use is for updating the status line.  It uses the same formatting buffer
// as the logger does, so don't let the logger use this.

static void near myCprintf( uint8_t x, uint8_t y, uint8_t attr, char *fmt, ... ) {

  va_list ap;
  va_start( ap, fmt );
  int bytesOut = vsnprintf( logLineBuffer, LOGFILE_MAX_ENTRY_SIZE, fmt, ap );
  va_end( ap );

  if ( bytesOut > (LOGFILE_MAX_ENTRY_SIZE-1) ) {
    // Truncated output - better than nothing
    logLineBuffer[LOGFILE_MAX_ENTRY_SIZE-1] = 0;
  }
  else if ( bytesOut < 0 ) {
    // Internal error - find and fix this!
    strcpy( logLineBuffer, InternalLoggingError );
    bytesOut = sizeof(InternalLoggingError) - 1;
  }

  #ifndef BIOS_SCREEN_WRITES
  uint16_t far *start = (uint16_t far *)(Screen_base + (y*ScreenCols+x));

  for ( uint16_t i = 0; i < bytesOut; i++ ) {
    *start++ = ( attr << 8 | logLineBuffer[i] );
  }
  #else
  for ( uint16_t i = 0; i < bytesOut; i++ ) {
    writeChar( x, y, logLineBuffer[i], attr );
    x++;
  }
  #endif

}

