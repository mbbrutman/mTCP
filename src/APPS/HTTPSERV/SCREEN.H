/*

   mTCP HTTPServ Screen.h
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


   Description: Screen handling header file for the http server.

*/


#ifndef _SCREEN_H
#define _SCREEN_H

#include "types.h"



// Screen messages and log handling
//
// mTCP provides a trace mechanism which is good for socket level debugging
// but it does not provide enough control/granularity for a complex program
// like this.  So we add a second level of logging that consists of on-screen
// messages and a log file.
//
// Every message gets flagged with a severity level that determines if it
// gets written to the screen or not.  By default every message is written
// to the log file and every message gets timestamped.  Optional flags can
// override those defaults.
//
// Messages that are not to be logged are assumed to be local messages for
// the screen only, probably an informational message.  These messages will
// be highlighted.
//
// Anything that gets logged to the logfile also gets written to the mTCP
// trace buffer if it is active.
//
// LOG_DEBUG is a clever hack; debug messages are normally not interesting so
// we don't want to fill the log file with them.  But if the user is actually
// looking at them on the screen then log them too.


// Flags used for writing

#define MSG_ERROR      (0x00)    // Will also be highlighted on the screen
#define MSG_NORM       (0x01)
#define MSG_VERBOSE    (0x02)
#define MSG_DEBUG      (0x03)

#define MSG_FLAG_NOLOG  (0x10)
#define MSG_FLAG_NO_TS  (0x20)




// Screen Handling
//
// This is not as sophisticated as IRCjr or Telnet.
//
// Scrolling the screen is expensive.  Allocate enough memory to keep a
// virtual copy of the screen in memory.  Update that virtual copy when
// we need to write something on the console.  Refresh the entire
// console once or twice a second if needed.
//
// This gets us out of scrolling the console every time a message is
// posted.  We were scrolling efficiently - precounting the number of
// lines and doing a memmove.  But many messages were created one or
// two lines at a time, so for each call to add a message we were
// scrolling.  This method gets rid of that problem.
//
// It costs about 4KB extra for CGA, 12.6KB extra if you go 132x50.
// The performance boost is worth it.



// Data that needs to be shared globally

extern int ScreenCols, ScreenRows;
extern bool ScreenNeedsPainting;


// Functions

int8_t initScreen( void );
void   addToScreen( uint8_t flags, const char *fmt, ... );
void   paintScreen( void );
void   drawStaticArea( void );
void   redrawStatusLine( void );


// define this as a #define instead of function to avoid compiler warnings
// about redefinitions.
#define isScreenReady( ) (ScreenCols != 0)



// BIOS_SCREEN_WRITES is a #define that can be used to force HTTPSERV to
// only use the BIOS calls when writing to the screen.  That makes the screen
// output much slower, but it improves compatibility in some environments
// like DESQView.
//
// When it is used we basically have to do two calls to INT 10h for each
// character to be written.  That is horrible.  There is a newer function
// under INT1 10h which would be faster, but it's only available on AT
// level BIOSes so I don't use it here.
//
// if BIOS_SCREEN_WRITES is defined then paintScreenIfNeeded becomes
// a no-op.  Calls to paintScreen will still happen, but that becomes
// an empty function and there are only two calls to it, both at the
// end of the program so it's not worth removing.

#ifndef BIOS_SCREEN_WRITES
#define paintScreenIfNeeded( ) { if ( ScreenNeedsPainting ) paintScreen( ); }
#else
#define paintScreenIfNeeded( ) { }
#endif



// Log file functions
//
// flushLogs will flush out the in memory logs buffer and to disk.  This is
// an idle time or ending function.  flushLogsIfNeeded will only flush the
// in memory buffer if needed and it will not flush to disk for performance
// reasons.

extern void flushLogs_private( void );

#define flushLogs( ) {       \
  if (LogFileBufferBytes) {  \
    flushLogs_private( );    \
    fflush( LogFile );       \
  }                          \
}

#define flushLogsIfNeeded( ) { \
  if (LogFileBufferBytes > (LOGFILE_BUFFER_SIZE-LOGFILE_BUFFER_MARGIN) ) { \
    flushLogs_private( );                                                  \
  }                                                                        \
}



#endif
