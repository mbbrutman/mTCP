/*

   mTCP HTTPServ HttpServ.h
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


   Description: #defines and global definitions for the http server.

*/


#ifndef _HTTPSERV_H
#define _HTTPSERV_H


#include "Utils.h"


// Consistency checking should only be enabled during development.
// Do not ship code like this.
//
// The use of assert is a problem because it just bombs the program
// and does not unhook interrupt handlers.


/*
#define HTTPSRV_CONSISTENCY_CHECK
#define HTTPSRV_CHECK_NULLPTRS
#define HTTPSRV_CHECK_PARAMS
#define HTTPSRV_CHECK_CLIENTS_TABLE
#define HTTPSRV_CHECK_CLIENT_OBJ
#define HTTPSRV_CHECK_DIRCACHE
#define HTTPSRV_CHECK_REQUEST_OBJ
#define HTTPSRV_CHECK_STRLEN
*/



// Useful but not httpserver specific:

#define STRINGIZE_(x) #x
#define STRINGIZE(x) STRINGIZE_(x)


#define HTTP_PATH_COMPONENT_LEN (61)
#define HTTP_PATH_COMPONENTS    (20)
#define HTTP_AUTH_MAX_REALM_LEN (51)


// Configuration options for clients that are needed globally.

#define CLIENT_AUTH_MAX_USERID_LEN   (16)
#define CLIENT_AUTH_MAX_PASSWORD_LEN (12)


#define FILE_CACHE_MAX_ENTRIES (20)




// Application specific options


// MAX_CLIENTS is the maximum number of clients that can be connected
// and serviced at one time.  Your CPU and network bandwidth are shared
// so on slow machines each additional connected client is painful.
//
// Space is also a consideration; each client is around 512 bytes + 
// CLIENT_OUTPUT_BUFFER_SIZE + HTTP_REQUEST_BUFFER_SIZE +
// HTTP_REQUEST_URI_SIZE + HTTP_REQUEST_URI_PARMS_SIZE .

#define MAX_CLIENTS (8)


// CLIENT_OUTPUT_BUFFER_SIZE is the amount of storage allocated for each
// client.  The storage is used for buffering files when reading from disk
// or for building up output to satisfy a request.
//
#define CLIENT_OUTPUT_BUFFER_SIZE      (8192)


// CLIENT_TCP_BUFFER_SIZE is the amount of storage each socket has available
// for incoming data.  This should be big enough to accomodate reasonable
// HTTP requests.  If it is too small you slow down because of TCP window
// size and flow control.
//
#define CLIENT_TCP_BUFFER_SIZE         (1024)


#define SERVER_NAME_SIZE (60)

#define HTTP_REQUEST_URI_SIZE (128)
#define HTTP_REQUEST_URI_PARMS_SIZE (128)

// This value used to be set to 1K and limited to 2K.  Now the limit is 4K.
// There are clients out there that send very verbose requests.  We can't fix
// them all, but doubling to 2K might help some.
#define HTTP_REQUEST_BUFFER_SIZE (2048)

#define LOGFILE_MAX_ENTRY_SIZE   (768)  // Max size for a single write to the log
#define LOGFILE_BUFFER_SIZE    (16384)  // Total size of the in memory buffer
#define LOGFILE_BUFFER_MARGIN   (1024)  // Below this amount free we write to disk

// Payload for UDP logging messages + 28 bytes of IP and UDP header.
#define UDP_LOGGING_PAYLOAD (LOGFILE_MAX_ENTRY_SIZE+28)



// Sanity checking for the configuration options
//
static_assert( MAX_CLIENTS >=  1 );
static_assert( MAX_CLIENTS <= 10 );
static_assert( SERVER_NAME_SIZE >= 40 );
static_assert( SERVER_NAME_SIZE <= 80 );

static_assert( CLIENT_OUTPUT_BUFFER_SIZE >= 4096 );
static_assert( CLIENT_OUTPUT_BUFFER_SIZE <= 8192 );
static_assert( CLIENT_TCP_BUFFER_SIZE >= 1024 );
static_assert( CLIENT_TCP_BUFFER_SIZE <= 2048 );

static_assert( HTTP_REQUEST_URI_SIZE >= 64 );
static_assert( HTTP_REQUEST_URI_SIZE <= 256 );
static_assert( HTTP_REQUEST_URI_PARMS_SIZE >= 64 );
static_assert( HTTP_REQUEST_URI_PARMS_SIZE <= 256 );
static_assert( HTTP_REQUEST_BUFFER_SIZE >= 1024 );
static_assert( HTTP_REQUEST_BUFFER_SIZE <= 4096 );

static_assert( FILE_CACHE_MAX_ENTRIES >= 1 );
static_assert( FILE_CACHE_MAX_ENTRIES <= FILE_CACHE_MAX_ENTRIES );

static_assert( LOGFILE_MAX_ENTRY_SIZE >=  512 );
static_assert( LOGFILE_MAX_ENTRY_SIZE <= 1024 );
static_assert( LOGFILE_BUFFER_SIZE    >= 8192 );
static_assert( LOGFILE_BUFFER_SIZE    <= 32768 );
static_assert( LOGFILE_BUFFER_MARGIN  >  LOGFILE_MAX_ENTRY_SIZE );
static_assert( LOGFILE_BUFFER_MARGIN  <= (LOGFILE_BUFFER_SIZE/2) );




// Useful constants

#define CR (13)   // Carriage return
#define LF (10)   // Line feed
#define NL (10)   // Unix style newline

#define CRLF "\r\n"

#define HTACCESS_FILENAME "htaccess.---"



// Useful global variables

extern char ServerName[];

extern char *RealmsMap;

extern uint32_t Content_Long_Expires_Time;

extern char *GA_Script;


// Variables needed for screen handling and logging

extern uint32_t SessionCounter;
extern uint32_t ObjectsServed;
extern uint16_t ActiveClients;
extern uint8_t  Verbosity;
extern bool     BeepToggle;

extern char      LogFilename[];
extern char     *LogFileBuffer;
extern uint16_t  LogFileBufferBytes;
extern FILE     *LogFile;
extern bool      LogFilePaused;

extern uint8_t Shutdown;



// Stats

extern uint32_t HTTP_RC_200;
extern uint32_t HTTP_RC_301;
extern uint32_t HTTP_RC_304;
extern uint32_t HTTP_RC_400;
extern uint32_t HTTP_RC_401;
extern uint32_t HTTP_RC_403;
extern uint32_t HTTP_RC_404;
extern uint32_t HTTP_RC_414;
extern uint32_t HTTP_RC_500;


extern bool DirectoryIndexingAllowedDefault;

extern char HTTPDocs[DOS_MAX_PATH_LENGTH];
extern char HTTPZips[DOS_MAX_PATH_LENGTH];



// Function prototypes

char *getRealmPassword( const char *targetRealm );

#endif
