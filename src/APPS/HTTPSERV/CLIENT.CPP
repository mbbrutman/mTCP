/*

   mTCP HTTPSERV Client.cpp
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


   Description: Client side functions for the http server.

*/


#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <malloc.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


#include "timer.h"
#include "trace.h"
#include "utils.h"
#include "packet.h"
#include "arp.h"
#include "tcp.h"
#include "tcpsockm.h"

#include "client.h"
#include "screen.h"



// Data structures and constants used for interpreting directory entries.
// Taken from the Open Watcom C Library reference.

typedef union {
  unsigned short us;            // unsigned short
  struct {
    unsigned short twosecs : 5; // seconds / 2
    unsigned short minutes : 6; // minutes (0,59)
    unsigned short hours : 5;   // hours (0,23)
  } fields;
} ftime_t;

typedef union {
  unsigned short us;            // unsigned short
  struct {
    unsigned short day : 5;     // day (1,31)
    unsigned short month : 4;   // month (1,12)
    unsigned short year : 7;    // 0 is 1980
  } fields;
} fdate_t;

static const char *Months[] = {
  "Jan", "Feb", "Mar", "Apr", "May", "Jun",
  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

static const char *Days[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };


// This isn't great code.  But it worked on the first
// try, it is compact enough, and it should be rarely
// used.

int8_t base64Decoder( const char *input, char *output, int outputBufferSize ) {

  #ifdef HTTPSRV_CHECK_PARAMS
  assert( input != NULL );
  assert( output != NULL );
  assert( input != output );
  assert( outputBufferSize > 0 );
  #endif

  int8_t rc = 0;

  uint16_t outputIndex = 0;
  uint8_t bitOffset = 0;

  while (*input) {

    if ( outputIndex == (outputBufferSize-1) ) {
      // Overflow
      rc = -1;
      break;
    }

    uint8_t a = *input;
    uint8_t tmp = 0;

    if ( (a >= 'A') && (a <= 'Z') ) {
      tmp = a - 'A';
    }
    else {
      if ( (a >= 'a') && (a <= 'z') ) {
        tmp = a - 'a' + 26;
      }
      else {
        if ( (a >= '0') && (a <= '9') ){
          tmp = a - '0' + 52;
        }
      }
    }

    if ( bitOffset == 0 ) {
      output[outputIndex] = tmp << 2;
    } else if ( bitOffset == 6 ) {
      output[outputIndex] = output[outputIndex] | (tmp >> 4);
      outputIndex++;
      output[outputIndex] = tmp << 4;
    } else if ( bitOffset == 4 ) {
      output[outputIndex] = output[outputIndex] | (tmp >> 2);
      outputIndex++;
      output[outputIndex] = tmp << 6;
    } else if ( bitOffset == 2 ) {
      output[outputIndex] = output[outputIndex] | tmp;
      outputIndex++;
    }

    input++;

    bitOffset = (bitOffset + 6) & 7;

  }

  output[outputIndex] = 0;

  return rc;
}



//-----------------------------------------------------------------------------

const char *Request::HttpRequestNames[] = {
  "Host:",
  "User-Agent:",
  "Accept-Encoding:",
  "Authorization:",
  "Referer:",
  "Connection:",
  "If-Modified-Since:"
};


const char *Request::HttpVersionStrings[] = {
  "HTTP/0.9",
  "HTTP/1.0",
  "HTTP/1.1"
};


const char *Request::HttpMethodStrings[] = {
  "NOTSET",
  "GET",
  "HEAD"
};


const char *Client::States[] = {
  "Inactive",
  "ReadRequest",
  "SendingFile",
  "SendingCachedFile",
  "SendingDir",
  "RequestDone",
  "SocketErr",
  "ForceClose",
  "Closing"
};


//-----------------------------------------------------------------------------



// Request::~Request
//
// Used only at the end of the program.  Called when a client object is released.

Request::~Request( ) {

  if ( buffer == (uint8_t *)CLIENT_UNINITIALIZED_COOKIE ) {
    // Constructed with the minimal constructor but uninitialized - no problem.
    buffer = NULL;
  }
  else if ( buffer == NULL ) {
    fprintf( stderr, "Request: Error - tried to free a request buffer twice\n" );
  }
  else {
    free( buffer );
    free( uriString );
    free( uriParmString );
  }

}


// Request::init
//
// Only used once at the beginning of the program.  Allocates two largish
// buffers.

int8_t Request::init( void ) {

  buffer = (uint8_t *)mTCP_malloc( HTTP_REQUEST_BUFFER_SIZE, "HTTP_Client_Req_buf" );
  if ( buffer == NULL ) {
    buffer = (uint8_t *)CLIENT_UNINITIALIZED_COOKIE;
    return -1;
  }

  uriString = (char *)mTCP_malloc( HTTP_REQUEST_URI_SIZE, "HTTP_Client_URI" );
  if ( uriString == NULL ) {
    free( buffer );
    buffer = (uint8_t *)CLIENT_UNINITIALIZED_COOKIE;
    return -1;
  }

  uriParmString = (char *)mTCP_malloc( HTTP_REQUEST_URI_PARMS_SIZE, "HTTP_Client_Parms" );
  if ( uriParmString == NULL ) {
    free( uriString );
    free( buffer );
    buffer = (uint8_t *)CLIENT_UNINITIALIZED_COOKIE;
    return -1;
  }

  return 0;

}





#ifdef HTTPSRV_CHECK_REQUEST_OBJ
void Request::consistencyCheck( void ) {

  assert( this != NULL );

  assert( bufferIndex <= HTTP_REQUEST_BUFFER_SIZE );
  assert( parseIndex <= HTTP_REQUEST_BUFFER_SIZE );
  assert( httpVer <= Http11 );
  assert( httpMethod <= HEAD );
  assert( keepAliveState <= KeepAlive );
  assert( httpRc <= 500 );

  assert( buffer != NULL );
  assert( uriString != NULL );
  assert( uriParmString != NULL );

  #ifdef HTTPSRV_CHECK_STRLEN
  assert( strlen(uriString) < HTTP_REQUEST_URI_SIZE );
  assert( strlen(uriParmString) < HTTP_REQUEST_URI_PARMS_SIZE );
  assert( strlen(authUser) < CLIENT_AUTH_MAX_USERID_LEN );
  assert( strlen(authPass) < CLIENT_AUTH_MAX_PASSWORD_LEN );
  #endif

}
#endif



// Request::reset
//
// Call this to reset the request object for the next request.
// In case of an error you can pass in "false" to wipe out any
// unparsed bytes, although the client is probably going to
// get whacked and this object won't be used again.

void Request::reset( bool preserveUnusedBytes ) {

  consistencyCheck( );

  uint16_t unusedBytes = bufferIndex - parseIndex;

  if ( preserveUnusedBytes && unusedBytes ) {

    // TRACE(( "setupNext: found %d unused bytes\n", (bufferIndex - parseIndex) ));

    memmove( buffer, buffer+parseIndex, bufferIndex - parseIndex );
    bufferIndex = bufferIndex - parseIndex;
    newBytesToParse = true;

  }
  else {

    bufferIndex = 0;
    newBytesToParse = false;

  }

  parseIndex = 0;

  *uriString = 0;
  *uriParmString = 0;
  *authUser = 0;
  *authPass = 0;

  origUriString = NULL;

  for ( int i=0; i < LastString; i++ ) {
    requestValues[i] = NULL;
  }


  httpVer = Http09;
  httpMethod = NOTSET;
  keepAliveState = DefaultKeepAlive;
  gzipAccepted = false;
  ifModifiedSinceTime = 0;

  httpRc = 0;
}




// Request::readRequestBytes
//
// Reads the socket, filling in the buffer from the position where the
// last read left off.  This does not attempt to parse what it read.
//
// Returns -1 if there is a socket error, 0 otherwise.  We do not return
// the number of bytes read; instead we set a flag that indicates new
// bytes are available.  This lets us defer processing the bytes if we
// need to without losing track of the fact that they need processing.

int16_t Request::readRequestBytes( TcpSocket *socket ) {

  consistencyCheck( );

  #ifdef HTTPSRV_CHECK_PARAMS
  assert( socket != NULL );
  #endif

  int16_t recvRc = socket->recv( (buffer + bufferIndex), (HTTP_REQUEST_BUFFER_SIZE - bufferIndex) );

  if ( recvRc > 0 ) {
    // if ( Trace_Debugging) Utils::dumpBytes( Trace_Stream, buffer + bufferIndex, recvRc );
    bufferIndex += recvRc;
    newBytesToParse = true;
    recvRc = 0;
  }

  return recvRc;
}



// Request::parseAuthorization
//
// Authorization headers probably won't happen too often and this code is large
// enough were it should not be inline in the parsing routine.
//
// A parse error does not return an error; it just fails silently.  Maybe we
// should fix this.

// A static buffer big enough for decoding a userid and password.

#define TMPBUFFERSIZE ((CLIENT_AUTH_MAX_USERID_LEN + CLIENT_AUTH_MAX_PASSWORD_LEN)*2)
static char tmpBuffer[ TMPBUFFERSIZE ];

void Request::parseAuthorization( char *pos ) {

  // Be very safe ...
  authUser[0] = authPass[0] = 0;

  if ( *pos == 0 ) return;

  requestValues[Authorization] = pos;

  char tmpToken[10];
  pos = Utils::getNextToken( pos, tmpToken, 10 );

  if ( stricmp(tmpToken, "basic" ) != 0 ) {
    addToScreen( MSG_ERROR, "Unsupported Auth type: %s\n", tmpToken );
    return;
  }

  if ( pos == NULL ) return;

  while ( *pos && *pos == ' ' ) pos++;
  if ( *pos == 0 ) return;


  if ( base64Decoder( pos, tmpBuffer, TMPBUFFERSIZE ) ) {
    authUser[0] = authPass[0] = 0;
    return;
  }

  char *authStringPos = tmpBuffer;

  int i = 0;
  while ( *authStringPos && (*authStringPos != ':') && (i < CLIENT_AUTH_MAX_USERID_LEN) ) {
    authUser[i] = *authStringPos++;
    i++;
  }

  // If we stopped on the delimiter then we did not overflow the userid
  // field.  Otherwise, we overflowed and it is an error.

  if ( *authStringPos != ':' ) {
    // Overflowed the userid field.
    authUser[0] = authPass[0] = 0;
    return;
  }

  authStringPos++;
  authUser[i] = 0;

  i = 0;
  while ( *authStringPos && (i < CLIENT_AUTH_MAX_PASSWORD_LEN) ) {
    authPass[i] = *authStringPos++;
    i++;
  }

  // If we stopped on the NULL char then we did not overflow the
  // password field.

  if ( *authStringPos == 0 ) {
    authPass[i] = 0;
  }
  else {
    // Error
    authUser[0] = authPass[0] = 0;
  }

}


void Request::parseIfModifiedSince( char *pos ) {

  requestValues[IfModifiedSince] = pos;

  int hour, min, sec, day, year;
  char dayStr[4], monthStr[4];

  int rc = sscanf( pos, "%3s, %d %3s %d %d:%d:%d GMT", dayStr, &day, monthStr, &year, &hour, &min, &sec );

  if ( rc == 7 ) {

    // Do some error checking.  This is not perfect but it weeds out most problems.

    int month = -1;
    for ( int i=0; i < 12; i++ ) {
      if ( stricmp( monthStr, Months[i] ) == 0 ) { month = i; break; }
    }

    if ( (month >= 0)    && (month < 12) &&     // Month is zero based in this interface
         (day   >= 0)    && (day   < 32) &&     // 1 to 31
         (year  >= 1970) && (year  < 2100) &&
         (hour  >= 0)    && (hour  < 25) &&
         (min   >= 0)    && (min   < 61) &&
         (sec   >= 0)    && (sec   < 61) ) {

      struct tm inputTime;

      inputTime.tm_sec = sec;
      inputTime.tm_min = min;
      inputTime.tm_hour = hour;
      inputTime.tm_mday = day;
      inputTime.tm_mon = month;
      inputTime.tm_year = year - 1900;
      inputTime.tm_isdst = -1;

      ifModifiedSinceTime = mktime( &inputTime );

      time_t currentTime = time( NULL );

      // If the time passed in is greater than our current time it is invalid.
      if ( currentTime < ifModifiedSinceTime ) {
        ifModifiedSinceTime = 0;
      }

    }

  } // end if correct number of fields scanned

}



// Whether a character is reasonable or not depends on the context.  Some
// characters like spaces or : are also delimeters and may not be safe at
// a particular point in time.
//
// This check is used to weed out the obviously bad things.

inline bool IsReasonableChar( uint8_t target ) {
  return ((target > 31) && (target < 127));
}


char *NULLSTR = "";

// Request::parse2
//
// Given a raw request buffer from the client set pointers into the interesting
// parts of the request buffer.  Also modify the request buffer by replacing
// the CR/LF pairs with null chars to mark the end of each string so that we
// can use the pointers as C strings.  (The client will not look in the buffer
// directly; it will use methods to get the fields it needs.)
//
// Why do this?  To save space.  Copying fields sucks.
//
// Assume that most of the time we get the full text of the request at once.
// If this is not the case this should fail gracefully and not fill in the
// request pointer.  Somebody interactively typing is going to annoy us but
// it will work.
//
// parseIndex is where parsing should pickup from
// bufferIndex is the first byte that is not part of the buffer (Stop!)
//
//
// Error handling
//
// We're going to make a valiant effort to keep parsing the entire request
// even if we find things that we don't like early.  That gives us more to
// work with if we want to print debug information.
//
// To do this we are going to keep parsing until we get a complete HTTP/0.9
// request (which is always a single line) or until we see a blank line.
// We can set the return code to an error code but we won't break out of the
// loop early unless it is really garbled.
//
// We will break if we run out of input, if we think the request is complete,
// or if the request is horribly garbled.
//
//
// Pipelined requests
//
// Each time new data is read newBytesToParse is set to true.  Each time
// we attempt to parse data we set newBytesToParse to false.  This allows
// us to detect if we have something new to look at quickly.
//
// In simple cases the client sends one request at a time.  It is possible
// that the client is pipelining requests, and that we will have more data
// than what fits in our request buffer.  If we parse the request buffer
// and find the end of the request we will preserve the rest of the bytes
// for the next request.  If we don't find the end of the request then we
// will error out with an overflow and close the connection.

Request::ParseStatus Request::parse2( Client *c ) {

  consistencyCheck( );

  ParseStatus rc = Incomplete;


  // Assume that we are going to look at all of the bytes received so
  // far and reset this flag so that we know if new bytes that need
  // processing come in at a later time.

  newBytesToParse = false;


  // parseIndex tells us where to start parsing from.  We only parse
  // full lines (CR LF terminated) so parseIndex should only be updated
  // when we find a CR LF pair.

  // TRACE_WARN(( "Entry: parseIndex %d   bufferIndex %d\n", parseIndex, bufferIndex ));


  addToScreen( MSG_DEBUG, "%s: Parsing request\n", c->getRemoteHostName( ) );


  while ( parseIndex < bufferIndex ) {

    char *lineStart = (char *)(buffer + parseIndex);

    uint16_t i = 0;
    uint16_t inputLen = bufferIndex - parseIndex;


    // Scan ahead to the next CR/LF pair.  It is possible that only an LF is
    // present; tolerate that if it happens.  We are supposed to tolerate blank
    // lines up front but somebody else can implement that.

    while ( i < inputLen ) {
      if ( (lineStart[i] == CR) || (lineStart[i] == LF) ) break;
      if ( !IsReasonableChar( lineStart[i] ) ) {
        // TRACE_WARN(("Bad Char found, first 1024 of req buffer follow\n" ));
        // Utils::dumpBytes( Trace_Stream, buffer, 1024 ); 
        // TRACE_WARN(("Bad char 0x%02X found at byte: %d\n", lineStart[i], i ));
        // Utils::dumpBytes( Trace_Stream, (unsigned char *)lineStart, i+10 ); 
        rc = BadCharacters;
        break;
      }
      i++;
    }

    // Ran out of input or encountered a bad character, so exit the main while loop.
    if ( (i == inputLen) || (rc == BadCharacters) ) break;


    // Figure out how many characters were in the delimiter.
    //
    // A single LF or CR/LF is allowed.  Anything else is a parsing error.
    // The LF case will fall through, while the CR case has to inspect
    // the next character.

    uint8_t charsInDelimiter = 1;

    if ( lineStart[i] == CR ) {

      // We've seen a CR.  Advance to the next character to inspecct it.

      if ( (i+1) == inputLen ) {
        // Incomplete, but it better be an LF when we return.
        break;
      }

      if ( lineStart[i+1] == LF ) {
        charsInDelimiter++;
      } else {
        // CR was not followed by an LF.  That's an error.
        rc = GeneralParsingError;
        break;
      }

    }

    i += charsInDelimiter;


    // Great, found a CRLF or LF on the line.  Now we can parse it.
    //
    // - parseIndex is the start of the current line
    // - i now points to the start of the next line.
    //
    // After we parse this line we will update parseIndex to i (the next line)
    // and start again.  If all of the request has been read and there is more
    // in the buffer then parseIndex will be pointing to the start of the next
    // request.

    // Terminate the string with a NULL char instead of CR LF.
    lineStart[i-charsInDelimiter] = 0;


    // If this was an empty line then this request has been fully read.
    // (That applies to HTTP/1.0 and HTTP/1.1.  For HTTP/0.9 each request
    // is only one line.)
    //
    // Keep in mind that a blank line by itself can trick us.  We have to check
    // later to see if a method was specified; if not is an error.

    if ( lineStart[0] == 0 ) {
      // We just read an empty line.  Advance ParseIndex to where we should start parsing next.
      // When we started parseIndex was the beginning of the line, so we just need to advance
      // it past the delimiter characters.
      parseIndex += charsInDelimiter;
      rc = Complete;
      break;
    }


    // Parse the line.

    char token[30];
    char *pos = lineStart;
    pos = Utils::getNextToken( pos, token, 30 );

    // Optimization - it is easier to point to a null string than to keep checking
    // to see if pos is NULL.
    if ( pos == NULL ) pos = NULLSTR; 

    // Mov pos to the next non-space char.
    while ( *pos == ' ' ) pos++;

    // Fixme: need to scan for illegal characters before parsing.

    // HTTP verbs are case sensitive

    // pos will come back as NULL if the input was all whitespace or there was just one
    // token to parse.  Every HTTP header should have at least two tokens so that would
    // be an error.

    // TRACE_WARN(( "token: %s\n", token ));

    if ( parseIndex == 0 ) {

      // This is the first line, which is the only legal place a method can appear.
      // Only legal time to see a method.

      if ( (strcmp( token, "GET" ) == 0) || (strcmp( token, "HEAD" ) == 0) ) {

        if ( *pos == 0 ) {
          // No URI
          rc = GeneralParsingError;
          break;
        }

        if ( strcmp( token, "GET" ) == 0 ) {
          httpMethod = GET;
        } else if ( strcmp( token, "HEAD" ) == 0 ) {
          httpMethod = HEAD;
        }

        // Even if the URI is too long or causes a error during parsing try to
        // get to the end of the line to see if there is an HTTP version number.
        // If we don't get the version number we will assume HTTP/0.9 which
        // works, but we give better error codes to the client if it is a
        // better version of HTTP.
        //
        // Copy the URI to a new buffer where we can manipulate it.  Leave a
        // pointer to the original one for debugging.

        origUriString = pos;

        int j=0;
        while ( (*pos) && (*pos != ' ') && (*pos != '?') && (j < HTTP_REQUEST_URI_SIZE) ) {
          uriString[j] = *pos;
          pos++;
          j++;
        }

        if ( j == HTTP_REQUEST_URI_SIZE) {

          // The URI is too long.
          uriString[0] = 0;

          TRACE_WARN(( "Warning: incoming URI is too long.  Length = %u\n", strlen(origUriString) ));

          // Advance to the next space so that we can try to pick up the HTTP
          // protocol version number, if present.

          while ( (*pos) && (*pos != ' ') ) pos++;

          rc = UriTooLong;

        } else {

          // Stopped because we found a space or the start of parameters.
         
          // Terminate the URI string properly.
          uriString[j] = 0;

          // Collapse . and .. from the path and convert % encoded chars to
          // their native form.

          if ( removeDotSegments( uriString, HTTP_REQUEST_URI_SIZE) ) {
            uriString[0] = 0;
            rc = GeneralParsingError;
          }

          if ( *pos == '?' ) {

            pos++;

            // Copy parameters

            int k=0;
            while ( (*pos) && (*pos != ' ') && (k < HTTP_REQUEST_URI_PARMS_SIZE) ) {
              uriParmString[k] = *pos;
              pos++;
              k++;
            }

            if ( k == HTTP_REQUEST_URI_PARMS_SIZE ) {

              // Argh!  Parameters too long ...

              uriString[0] = 0;
              uriParmString[0] = 0;

              TRACE_WARN(( "Warning: incoming URI parms are too long.  Length = %u\n", strlen(origUriString) ));

              // Advance to the next space so that we can try to pick up the HTTP
              // protocol version number, if present.

              while ( (*pos) && (*pos != ' ') ) pos++;

              rc = UriParmsTooLong;

            } else {

              // Terminate the string.  We do not convert escaped characters
              // at this point; that will be deferred until somebody parses
              // the parameters.

              uriParmString[k] = 0;

            }

          } // End if parameters found.

        } // End if URI copied.


        // We assume that the HTTP version is 0.9 unless told otherwise.  If pos
        // is sitting on a null character then that is true.  Otherwise, pos
        // should be sitting at the space before the HTTP version string.

        // Skip extra spaces.  This should not be needed but we are being tolerant.
        while ( (*pos != 0) && (*pos == ' ') ) pos++;

        if ( (*pos != 0) && (strcmp(pos, "HTTP/1.0") == 0) ) {
          httpVer = Http10;
        }
        else if ( (*pos != 0) && (strcmp(pos, "HTTP/1.1") == 0) ) {
          httpVer = Http11;
        }

        if ( httpVer == Http09 ) {
          if ( rc == Incomplete ) rc = Complete;
          break;
        }

        if ( rc != Incomplete ) {
          // This must be an error - there is no point in continuing to parse headers.
          break;
        }

      } else {
        // Not GET or HEAD
        addToScreen( MSG_ERROR, "Unsupported HTTP method: %s\n", token );
        rc = GeneralParsingError;
        break;
      }

    } // end if on the first line of the request.

    else if ( stricmp( token, HttpRequestNames[Host] ) == 0 ) {
      if ( *pos ) requestValues[Host] = pos;
    }

    else if ( stricmp( token, HttpRequestNames[UserAgent] ) == 0 ) {
      if ( *pos ) requestValues[UserAgent] = pos;
      // if ( *pos ) {
      //   if ( stricmp(pos, "HTTrack") == 0 ) {
      //    rc = Blocked;
      //    break;
      //   }
      // }
    }

    else if ( stricmp( token, HttpRequestNames[Referer] ) == 0 ) {
      if ( *pos ) requestValues[Referer] = pos;
    }

    else if ( stricmp( token, HttpRequestNames[Authorization] ) == 0 ) {
      parseAuthorization( pos );
    }

    else if ( stricmp( token, HttpRequestNames[Connection] ) == 0 && (*pos) ) {

      requestValues[Connection] = pos;

      char tmpToken[20];
      Utils::getNextToken( pos, tmpToken, 20 );

      if ( stricmp( tmpToken, "close" ) == 0 ) {
        keepAliveState = NoKeepAlive;
      }
      else if ( stricmp( tmpToken, "keep-alive" ) == 0 ) {
        keepAliveState = KeepAlive;
      }

    }

    else if ( (stricmp( token, HttpRequestNames[AcceptEncoding] ) == 0) && (*pos) ) {

      requestValues[AcceptEncoding] = pos;

      // First, search for x-gzip.  If we find it we are done; there is no q value
      // to parse with that.

      char *start = strstr( pos, "x-gzip" );

      if ( start != NULL ) {

        gzipAccepted = true;

      }
      else {

        // Scan the encoding string for gzip.  If we find the gzip string
        // assume they can accept it unless they do something stupid like
        // set the q value to 0.

        start = strstr( pos, "gzip" );

        if ( start != NULL ) {

          gzipAccepted = true;

          // We want a floating point value but we don't want the floating
          // point library.  So be clever and use two integer values instead.
          int a = 0, b = 0;
          int rc = sscanf( start, "gzip;q=%d.%d", &a, &b );

          if ( (rc > 0) && ((a > 0) || (b > 0)) ) gzipAccepted = false;

        }

      }

    }

    else if ( stricmp( token, HttpRequestNames[IfModifiedSince] ) == 0 && (*pos) ) {
      parseIfModifiedSince( pos );
    } // end If-Modified-Since header

    else {
      addToScreen( MSG_DEBUG, "Unparsed request header: %s %s\n", token, pos );
    }


    // This line is now parsed whether we cared about the contents or not.
    // Set the parseIndex up to start on the next line.

    parseIndex += i;

  } // end while



  // We broke out of the loop because we are incomplete, we are complete,
  // or we have an error to report.
  //
  // If we think we are complete there had better be a URI.  If not, convert
  // that to a parsing error.
  //
  // If we are incomplete and the request buffer was filled then they sent
  // us too much data.  Maybe there were a bunch of headers that we don't
  // care about.  If the URI is present then we can try to serve it anyway
  // because most of the headers are not required to serve.  The additional
  // bytes that we could not read into the buffer are going to look like
  // garbage.
  //
  // If it is a error already then there is not much we can do about it.
  // Just let it pass through to the caller.

  if ( rc == Complete ) {
    if ( origUriString == NULL ) rc = GeneralParsingError;
  }
  else if ( rc == Incomplete ) {

    // Incomplete request.  If the request buffer has room then we can go back
    // and wait on the socket for more data.  But if it is out of room then we
    // are hosed.

    if ( bufferIndex == HTTP_REQUEST_BUFFER_SIZE ) rc = RequestOverflowed;

  }


  // In the event of a hard error (Overflowed or GeneralParsingError) our
  // caller will send a haiku and force the connection closed.

  return rc;
}





static char convertHexCharToDec( char c ) {
  if ( c >= '0' && c <= '9' ) return c - '0';
  if ( c >= 'a' && c <= 'f' ) return c - 'a' + 10;
  if ( c >= 'A' && c <= 'F' ) return c - 'A' + 10;
  return 128;
}



// removeDotSegments takes a user path and breaks it up into components.
// Along the way it checks for . or .. and collapses them out as
// appropriate.  A rewritten path is returned.  A 1 is returned on error.
//
// Preserve any trailing directory delimiter.

static char component[HTTP_PATH_COMPONENTS][HTTP_PATH_COMPONENT_LEN];

uint16_t Request::removeDotSegments( char *path, int pathLen ) {

  #ifdef HTTPSRV_CHECK_PARAMS
  assert( path != NULL );
  #endif

  // First, skip past any http://server/ if it is present.

  int pathIndex = 0;

  if ( strncmp( path, "http://", 7 ) == 0 ) {

    // Scan ahead to end of host name
    pathIndex = 7;
    while ( (path[pathIndex] != 0) && (path[pathIndex] != '/') ) { pathIndex++; }

    // Leave with i pointing at the '/'.  If we ran off the end of the path
    // we'll detect that very shortly.
  }

  // Enforce a leading slash
  if ( path[pathIndex] != '/' ) return 1;

  int top = 0;


  bool lastCharWasDelimiter;

  pathIndex++;

  while ( path[pathIndex] ) {

    lastCharWasDelimiter = true;

    if ( top == HTTP_PATH_COMPONENTS ) return 1;

    // Read next component from the path

    char tmp[HTTP_PATH_COMPONENT_LEN];
    int tmpIndex = 0;

    while ( path[pathIndex] != 0 ) {

      if ( path[pathIndex] == '/' ) {
        lastCharWasDelimiter = true;
        pathIndex++;
        break;
      }

      lastCharWasDelimiter = false;

      if ( tmpIndex > (HTTP_PATH_COMPONENT_LEN-1) ) {
        // Out of space
        return 1;
      }

      if ( path[pathIndex] == '%' ) {
        pathIndex++;
        if ( path[pathIndex] == 0 ) return 1;
        else {
          char c1 = convertHexCharToDec(path[pathIndex]);
          pathIndex++;
          if ( path[pathIndex] == 0 ) return 1;
          char c2 = convertHexCharToDec(path[pathIndex]);
          if ( (c1 == 128) || (c2 == 128) ) return 1;
          tmp[tmpIndex] = (c1 * 16) + c2;
        }
      }
      else {
        tmp[tmpIndex] = path[pathIndex];
      }

      pathIndex++;
      tmpIndex++;

    }
    tmp[tmpIndex] = 0;


    if ( tmp[0] == 0 ) {
      if ( path[pathIndex] == 0 ) {
        // Empty component and end of input ..  end main loop.
        break;
      }
      else {
        // Empty component, but not end of input.  Must have been
        // back to back slashes.  We don't tolerate this.
        return 1;
      }
    }

    if ( strcmp( tmp, ".." ) == 0 ) {
      if ( top > 0 ) {
        top--;
      }
    }
    else if ( strcmp( tmp, "." ) == 0 ) {
      // Do nothing
    }
    else if ( tmp[0] ) {
      // Add it to the stack
      strcpy(component[top], tmp );
      top++;
    }

  }


  path[0] = 0;

  // If we wind up with no components at all then we are at the root.
  // Otherwise, construct the normalized path.

  if ( top == 0 ) {
    path[0] = '/';
    path[1] = 0;
  }
  else {

    for ( int i=0; i < top; i++ ) {

      // If we are going to overflow the path by adding another
      // delimiter and component then return an error.

      if ( strlen(path) + 1 + strlen(component[i]) >= pathLen ) return 1;

      strcat( path, "/" );
      strcat( path, component[i] );
    }

    if ( lastCharWasDelimiter ) {
      if ( strlen(path) < (pathLen-1) ) strcat( path, "/" ); else return 1;
    }
  }

  return 0;
}



// Request::setResponseCode
//

void Request::setResponseCode( uint16_t rc ) {

  httpRc = rc;

  switch ( rc ) {
    case 200: HTTP_RC_200++; break;
    case 301: HTTP_RC_301++; break;
    case 304: HTTP_RC_304++; break;
    case 400: HTTP_RC_400++; break;
    case 401: HTTP_RC_401++; break;
    case 403: HTTP_RC_403++; break;
    case 404: HTTP_RC_404++; break;
    case 414: HTTP_RC_414++; break;
    case 500: HTTP_RC_500++; break;
    default: {
      addToScreen( MSG_ERROR, "Bug: %l HTTP response not tracked in stats\n", rc );
    }
  }

}



// Request::getNextParm
//
// Parses the input string and returns the next name and value pair from
// the string.  If there are escaped characters in the strings they will
// be converted.
//
// Returns the next position to read from or NULL if the end of string was hit.
//
// If there is a parsing error it returns NULL and zeros out the strings.
// Parsing is fairly lenient; we insist that the name be present but not
// the value.

char *Request::getNextParm( char *input, char *name, uint16_t nameLen, char *value, uint16_t valueLen ) {

  #ifdef HTTPSRV_CHECK_PARAMS
  assert( input != NULL );
  assert( name != NULL );
  assert( value != NULL );
  #endif

  bool errorFlag = false;

  name[0] = 0;
  value[0] = 0;

  if ( input == NULL ) return NULL;

  int i=0;
  while ( (*input) && (*input != '=') && (*input != '&') && (*input != ';') ) {

    if ( i == nameLen ) { errorFlag = true; break; }

    if ( *input == '%' ) {
      input++;
      if ( *input == 0 ) { errorFlag = true; break; }
      uint8_t c1 = convertHexCharToDec(*input++);
      if ( *input == 0 ) { errorFlag = true; break; }
      uint8_t c2 = convertHexCharToDec(*input++);
      if ( (c1 == 128) || (c2 == 128) ) { errorFlag = true; break; }
      name[i++] = (c1 * 16) + c2;
    }
    else {
      name[i++] = *input++;
    }

  }

  if ( (i == 0) || errorFlag ) {
    name[0] = 0;
    return NULL;
  }

  name[i] = 0;

  if ( *input == '=' ) {

    input++;
    i=0;
    while ( (*input) && (*input != '&') && (*input != ';') ) {

      if ( i == valueLen ) { errorFlag = true; break; }

      if ( *input == '%' ) {
        input++;
        if ( *input == 0 ) { errorFlag = true; break; }
        uint8_t c1 = convertHexCharToDec(*input++);
        if ( *input == 0 ) { errorFlag = true; break; }
        uint8_t c2 = convertHexCharToDec(*input++);
        if ( (c1 == 128) || (c2 == 128) ) { errorFlag = true; break; }
        value[i++] = (c1 * 16) + c2;
      }
      else {
        value[i++] = *input++;
      }

    }

    if ( errorFlag ) {
      name[0] = 0; value[0] = 0;
      return NULL;
    }

    value[i] = 0;

  }

  if ( *input == '&' || *input == ';' ) input++;

  if ( *input == 0 ) {
    return NULL;
  }
  else {
    return input;
  }

}



// ----------------------------------------------------------------------------
//
// ClientTable and friends
//
// ClientTable is the array of client objects.  ClientTableIndex is used to
// give the illusion of a ClientTable where all of the in-use clients are
// contiguous.  Indexing adds a layer of indirection but it makes it easier
// to keep the active clients logically contiguous when a client is removed.
// We could do it the hard way, which involves carefully copying all of the
// fields of the client.  Or we could just swap indexes in the table.


uint16_t  Client::allocatedClients;
uint16_t  Client::activeClients;
Client   *Client::clientTableIndex[MAX_CLIENTS];
Client    Client::clientTable[MAX_CLIENTS];




#ifdef HTTPSRV_CHECK_CLIENTS_TABLE

uint16_t Client::areClientsAvailable( void ) {
  assert( activeClients <= allocatedClients );
  assert( allocatedClients <= MAX_CLIENTS );
  return activeClients < allocatedClients;
};

uint16_t Client::getActiveCount( void ) {
  assert( activeClients <= allocatedClients );
  assert( allocatedClients <= MAX_CLIENTS );
  return activeClients;
};

Client *Client::getClient( int16_t index ) {
  assert( index < allocatedClients );
  assert( activeClients <= allocatedClients );
  assert( allocatedClients <= MAX_CLIENTS );
  assert( clientTableIndex[index] != NULL );
  return clientTableIndex[index];
};

#endif





// Client::initClients
//
// If this fails then the program should be ending.  We are using
// destructors on the httpRequest objects so the allocated memory
// will be cleaned up automatically.

int8_t Client::initClients( uint16_t maxClients_p ) {

  allocatedClients = maxClients_p;

  for ( int i=0; i < allocatedClients; i++ ) {

    clientTable[i].socket = NULL;
    clientTable[i].setState( Inactive );

    // Explicitly initialize the embedded request object
    if ( clientTable[i].httpRequest.init( ) == -1 ) return -1;

    // If this fails the previously constructed embedded request objects
    // will be cleaned up by their destructors.
    clientTable[i].outputBuffer = (char *)mTCP_malloc( CLIENT_OUTPUT_BUFFER_SIZE, "HTTP_ClientOutput" );
    if ( clientTable[i].outputBuffer == NULL ) return -1;

  }

  // All objects constructed and no allocation problems.  Create the index.

  for ( int i=0; i < allocatedClients; i++ ) {
    clientTableIndex[i] = &clientTable[i];
  }

  activeClients = 0;

  return 0;

}



// Create a new client using a newly accepted socket.  If this fails return NULL.

Client * Client::allocateNewClient( TcpSocket *newSocket ) {

  #ifdef HTTPSRV_CHECK_PARAMS
  assert( newSocket != NULL );
  assert( newSocket->dstHost[0] != 0 );
  #endif
  #ifdef HTTPSRV_CHECK_CLIENTS_TABLE
  assert( activeClients <= allocatedClients );
  assert( allocatedClients <= MAX_CLIENTS );
  #endif

  if ( activeClients == allocatedClients ) return NULL;

  Client *tmp = clientTableIndex[activeClients];

  #ifdef HTTPSRV_CHECK_CLIENTS_TABLE
  assert( tmp != NULL );
  #endif

  // Setup for a new client

  tmp->httpRequest.reset( false );

  tmp->socket = newSocket;
  sprintf( tmp->remoteHostName, "%d.%d.%d.%d:%u",
           tmp->getSocket( )->dstHost[0], tmp->getSocket( )->dstHost[1],
           tmp->getSocket( )->dstHost[2], tmp->getSocket( )->dstHost[3],
           tmp->getSocket( )->dstPort );

  tmp->setState( ReadRequest );

  tmp->forceCloseWhenDone = false;

  // Things that should be set when first used by the client.
  // Add asserts to verify this.
  //
  // outputBuffer: persistent - never touched
  // outputBufferIndex: gets initialized by sendDirectory
  // fileHandle: gets initialized and reset
  // fileinfo: gets initialized and reset
  // findRc: gets initialized
  // fileinfoActive: gets initialized and reset


  // By this point everything is good
  activeClients++;

  return tmp;
}



// Client::releaseClient
//
// Call this when you are all done with the client.  (The socket should
// be closed.)
//
// This is going to release any resources that were in use by this client.
// That includes the TCP/IP socket, a possible open file handle, a possible
// open fileinfo structure, and anything else related.  Not all fields are
// reset to new - that will get done the next time this client is allocated.

void Client::releaseClient( Client *target ) {

  #ifdef HTTPSRV_CHECK_PARAMS
  assert( target != NULL );
  assert( target->socket->isClosed() );
  #endif

  // Scan the client table for the target.  If it is found return the resources.
  // Then take the last active client in the table and swap the two so that the
  // active table has no holes in it.  Be careful swapping; the request buffer
  // follows the client object around.

  // Swapping is actually done by swapping indexes to clients.  This is safer
  // than swapping clients and having to worry about individual fields getting
  // swapped correctly.

  int16_t targetIndex = -1;

  for ( int i=0; i < activeClients; i++ ) {
    if ( target == clientTableIndex[i] ) {
      targetIndex = i;
      break;
    }
  }

  #ifdef HTTPSRV_CHECK_CLIENTS_TABLE
  assert( targetIndex != -1 );
  #endif


  // Cleanup any resources that were in use during its lifetime.

  target->closeFileHandle( );
  target->closeFileinfo( );

  TcpSocketMgr::freeSocket( target->socket );
  target->socket = NULL;
  target->httpRequest.reset( false );
  target->setState( Inactive );

  activeClients--;

  // Swap the index pointers.  Avoids the overhead of copying the fields of the objects.
  // Target is holding a pointer to the client (verified above).

  clientTableIndex[targetIndex] = clientTableIndex[ activeClients];
  clientTableIndex[activeClients] = target;

}




// ----------------------------------------------------------------------------

Client::~Client( ) {

  if ( outputBuffer == (char *)CLIENT_UNINITIALIZED_COOKIE ) {
    // Uninitialized - no problem
    outputBuffer = NULL;
  }
  else if ( outputBuffer == NULL ) {
    fprintf( stderr, "Client: Error - tried to free a outputBuffer twice\n" );
  }
  else {

    // Should not need these here but we want to be safe and thorough.
    // (We should not be tearing down an object that is in use.)

    closeFileHandle( );
    closeFileinfo( );
    if ( socket != NULL ) TcpSocketMgr::freeSocket( socket );

    // This is all that should be needed in the destructor.
    free( outputBuffer );

  }

}



#ifdef HTTPSRV_CHECK_CLIENT_OBJ
void Client::consistencyCheck( void ) {
  assert( this != NULL );
  httpRequest.consistencyCheck( );
  assert( outputBufferIndex < CLIENT_OUTPUT_BUFFER_SIZE );
  assert( outputBuffer != NULL );
  assert( socket != NULL );
  assert( state <= Closing );
}
#endif



// Client::send
//
// We need a simple mechanism to push small things out to the client.
// Larger things like directory listings and files have to be able to
// stop and resume because of the large amounts of data, but for small
// amounts of data we will use this.
//
// The danger here is that this is effectively a blocking call.  The
// client can do something like close their receive window and leave
// us stuck in this loop.  We don't use keep-alives so it will be
// stuck forever.  To get around we will use a simple timer; if we can't
// make progress in 5 seconds the client gets killed.
//
// Return codes:
//
// *  0 - everything was sent.
// * -1 if there is an error.  On error the client is marked as closing.
//
// Remember, only send small amounts of data, as it's possible to DoS
// yourself if you send large amounts.  Remember, this is effectively a
// blocking call.
//
// Do not do an early return ...  you must make the Timer_stopManagingTimer
// call or you are going to have a bad time.

// This can probably be on the stack but I'm paranoid.  It is also easier
// to debug if it is in a fixed place.
static uint16_t clientSendTimer;

int16_t Client::send( uint8_t *userBuf, uint16_t userBufLen ) {

  #ifdef HTTPSRV_CHECK_PARAMS
  assert( userBuf != NULL );
  #endif

  consistencyCheck( );

  Timer_SetCountdownTimerMs( clientSendTimer, TCP_CLOSE_TIMEOUT );
  Timer_manageTimer( &clientSendTimer );

  uint16_t bytesSent = 0;
  int16_t rc = 0;

  while ( userBufLen > 0 ) {

    if ( Timer_isExpired( clientSendTimer ) ) {
      rc = -1;
      break;
    }

    int16_t sendRc = getSocket()->send( (userBuf + bytesSent), userBufLen );
    if ( sendRc > 0 ) {
      bytesSent += sendRc;
      userBufLen -= sendRc;
    }
    else if ( sendRc < 0 ) {
      setState( SocketError );
      rc = -1;
      break;
    }
    else {
      // If you can't make progress then process some packets
      Utils::processPackets( );
    }

  }

  Timer_stopManagingTimer( &clientSendTimer );
  return rc;
}





//-----------------------------------------------------------------------------
//
// Client::send301ForDirectory
//
// This is sent when the user requests something that is a directory but does
// not put the trailing slash on it.  Make sure the connection stays open for
// a quicker turn around time on the next request, which will no doubt include
// the trailing slash.

static const char private301_MessageBody[] = 
  "<html>"
    "<head>"
      "<title>"
        "301 Moved Permanently"
      "</title>"
    "</head>"
    "<body>"
      "Moved permanently! New location: http://%s%s/"
    "</body>"
  "</html>";


static char private_301Buffer[256];

void Client::send301ForDirectory( void ) {

  consistencyCheck( );

  httpRequest.setResponseCode( 301 );

  char *localURIString = httpRequest.getURIString( );

  // Predict the contentLen up front so we can keep the connection open.
  // The -4 is because the %s%s in the string will be replaced.
  uint16_t contentLen = strlen(private301_MessageBody) + strlen(ServerName) +
                        strlen(localURIString) - 4;

  if ( httpRequest.httpVer > Request::Http09 ) {

    if ( snprintf( private_301Buffer, 256, "Location: http://%s%s/" CRLF, ServerName, localURIString ) > 256 ) {
      TRACE_WARN(( "Client::send301: overflow formatting Location header\n" ));
      send500InternalError( );
    }
    else {
      if( sendHeaders( 301, "Moved Permanently", false, false, false, false, contentLen, "text/html",
                       Expires_DoNotSend, private_301Buffer, "301Err" ) ) return;
    }

  }


  // Headers are sent.  Now we can send the body.
  //
  // Not going to check for a buffer overrun here because the client output
  // buffer is ginormous compared to this content.  At worst case we'll just
  // send truncated content.

  if ( httpRequest.getHttpMethod( ) == Request::GET ) {

    // Not checking the return code, too small to overflow.
    uint16_t outputBytes = snprintf( outputBuffer, CLIENT_OUTPUT_BUFFER_SIZE, private301_MessageBody,
                                     ServerName,
                                     localURIString );

    if ( send( (uint8_t *)outputBuffer, outputBytes ) == -1 ) return;
  }

  setState( ReqDone );

}




// sendHaiku
//
// A hiaku is usually a response to an error.  For a soft error we can try to
// keep the connection open, assuming the client supports.  For a hard error
// just force the client to close.

static const char private_400_Header[] = "Bad Request";
static const char private_403_Header[] = "Forbidden";
static const char private_404_Header[] = "Not Found";
static const char private_414_Header[] = "URI too long";

static const char private_400Haiku[] =
  "<html>"
    "<head><title>400 Bad Request</title></head>"
    "<body><i>The request you made<br>confuses and confounds me<br>and thus does not work</i></body>"
  "</html>";

static const char private_403Haiku[] =
  "<html>"
    "<head><title>403 Forbidden</title></head>"
    "<body><i>The web page you seek<br>is forbidden for viewing<br>and that makes us sad</i></body>"
  "</html>";


static const char private_404Haiku[] =
  "<html>"
    "<head><title>404 Not Found</title></head>"
    "<body><i>The web page you seek<br>Cannot be located, but<br>Countless more exist</i></body>"
  "</html>";

static const char private_414Haiku[] =
  "<html>"
    "<head><title>414 Request URI Overflow</title></head>"
    "<body><i>The resource request<br>is too long for me to parse<br>so I must decline</i></body>"
  "</html>";

void Client::sendHaiku( uint16_t code, bool forceClose ) {

  consistencyCheck( );

  const char *haikuHeader;
  const char *haikuString;

  httpRequest.setResponseCode( code );

  switch ( code ) {

    case 400: haikuHeader = private_400_Header; haikuString = private_400Haiku; break;
    case 403: haikuHeader = private_403_Header; haikuString = private_403Haiku; break;
    case 404: haikuHeader = private_404_Header; haikuString = private_404Haiku; break;
    case 414: haikuHeader = private_414_Header; haikuString = private_414Haiku; break;

    default: {

      // Zero tolerance during development.  But if it leaks out to the real world
      // send an internal server error message.

      #ifdef HTTPSRV_CONSISTENCY_CHECK
      assert( 0 );
      #endif

      TRACE_WARN(( "Unknown Haiku code: %d\n", code ));
      send500InternalError( );

      return;
    }

  }

  int haikuLen = strlen( haikuString );

  if ( httpRequest.getHttpVersion() > Request::Http09 ) {

    if ( sendHeaders( code, haikuHeader, forceClose, false, false, false, haikuLen, "text/html",
                      Client::Expires_DoNotSend, NULL, "sendHaiku" ) ) 
    {
      return;
    }

  }

  if ( httpRequest.getHttpMethod( ) == Request::GET ) {
    if ( send( (uint8_t *)haikuString, haikuLen ) == -1 ) return;
  }

  setState( Client::ReqDone );
}



static const char private401_MessageBody[] =
  "<html>"
    "<head><title>401 Not authorized</title></head>"
    "<body><i>The page you desire<br>needs a password to be seen<br>and thus is denied</i></body>"
  "</html>";

// Fixme: See if we can combine this with another static temporary buffer or reduce it.
static char extraHeader[256];

void Client::send401NeedsAuth( const char *realm ) {

  consistencyCheck( );

  httpRequest.setResponseCode( 401 );

  if ( httpRequest.httpVer > Request::Http09 ) {

    // Use the outputBuffer for this extra header; it is more than large enough
    // so I'm not going to check for buffer overflows.  (The outputBuffer
    // is a minimum of 4KB in size.)

    sprintf( extraHeader, "WWW-Authenticate: Basic realm=\"%s\"\n", realm );

    if( sendHeaders( 401, "Not Authorized", false, false, false, false, (sizeof(private401_MessageBody)-1), NULL,
                     Expires_DoNotSend, extraHeader, "401Err" ) ) return;

  }

  if ( httpRequest.getHttpMethod( ) == Request::GET ) {
    if ( send( (uint8_t *)private401_MessageBody, (sizeof(private401_MessageBody)-1) ) == -1 ) return;
  }

  setState( ReqDone );

}


//-----------------------------------------------------------------------------
//
// Client::send500InternalError
//
// This generates the header of last resort - a 500.  As a result, it should
// be designed not to fail.  This will send a minimal set of headers and body
// text to ensure that we do not overflow.
//
// If you call this your client is done.  It will be told to close.
// Anything that calls this should be creating a warning in the trace.

static const char private_505InternalError[] =
  "%s 500 Internal server error" CRLF
  "%s"
  CRLF;

void Client::send500InternalError( void ) {

  consistencyCheck( );

  httpRequest.setResponseCode( 500 );
  if ( httpRequest.httpVer > Request::Http09 ) {

    // This is really small and will not overflow.  If it does somebody royally screwed up.
    uint16_t headerBytes = snprintf( outputBuffer, CLIENT_OUTPUT_BUFFER_SIZE, private_505InternalError,
                                     httpRequest.getHttpVersionStr( ),
                                     getCloseHeader( true ) );

    if ( send( (uint8_t *)outputBuffer, headerBytes ) == -1 ) return;

  }


  // All headers are sent.  It is safe to reuse outputBuffer again.

  if ( httpRequest.getHttpMethod( ) == Request::GET ) {

    // The body text is basically the same as the header.  This is to save
    // space on something that should not be happening.

    // Also too small to overflow.
    uint16_t outputBytes = snprintf( outputBuffer, CLIENT_OUTPUT_BUFFER_SIZE, private_505InternalError,
                                     httpRequest.getHttpVersionStr( ),
                                     "Please report this to the web master" CRLF );

    if ( send( (uint8_t *)outputBuffer, outputBytes ) == -1 ) return;
  }

  setState( ForceClose );

}


//-----------------------------------------------------------------------------
//
// sendDirectory
//
// Serve a directory listing in a simple HTML format.  If the client did not
// use the correct URI for the directory send back a 301 to let them know
// what the correct URI is.
//
// Directory listings might result in a lot of output so make this
// restartable to allow other clients to get work done.
//
// There are a lot of early returns in this code.  The caller should not
// assume that the connection is open and the client is alive after calling
// this.

static char directoryDelimiter[] = {0, 0};

void Client::sendDirectory( void ) {

  consistencyCheck( );

  if ( getState( ) == ReadRequest ) {

    // First time called for a directory request.

    outputBufferIndex = 0;

    if ( httpRequest.httpVer > Request::Http09 ) {

      // Always force the connection closed after a directory because I am
      // too lazy to do the chunked transfer method.

      httpRequest.setResponseCode( 200 );
      if ( sendHeaders( 200, "OK", true, false, false, false, 0, "text/html", Expires_5Minutes, NULL, "SendDir" ) ) return;

    }

    if ( httpRequest.getHttpMethod( ) == Request::HEAD ) {
      setState( ReqDone );
      return;
    }


    strcpy( outputBuffer + outputBufferIndex, "<html><head></head><body><pre>" );
    outputBufferIndex += 30;

    strcat( fullPath, "\\*.*" );

    findRc = _dos_findfirst( fullPath, (_A_NORMAL | _A_SUBDIR), &fileinfo );
    fileinfoActive = true;

    setState( SendingDirectory );

  }


  // This is a good place to DOS attack ourselves.  To avoid that limit the
  // amount of output we will send before interleaving with other clients.
  // The maximum amount of output is set to 4KB, which will fit comfortably
  // 3 Ethernet size frames.

  uint16_t outputLimit = CLIENT_OUTPUT_BUFFER_SIZE-512;
  if ( outputLimit > 4096 ) outputLimit = 4096;

  while ( 1 ) {

    if ( findRc == 0 ) {

      if ( stricmp( fileinfo.name, HTACCESS_FILENAME ) != 0 ) { 

        // Format file attributes
        char attrs[] = "-rwxrwxrwx"; // Default
        if ( fileinfo.attrib & _A_SUBDIR ) { attrs[0] = 'd'; }
        if ( fileinfo.attrib & _A_RDONLY ) { attrs[2] = attrs[5] = attrs[8] = '-'; }

        ftime_t ft;
        ft.us = fileinfo.wr_time;

        fdate_t fd;
        fd.us = fileinfo.wr_date;

        if ( fileinfo.attrib & _A_SUBDIR ) directoryDelimiter[0] = '/'; else directoryDelimiter[0] = 0;

        // We left a minimum of 512 bytes in the buffer for this string.
        // It will not overflow.

        uint16_t rc = 0;
        rc = sprintf( (char *)(outputBuffer + outputBufferIndex), "%s %10lu %s %2d %4d %02d:%02d <a href=\"%s%s\">%s</a>" CRLF,
                    attrs, fileinfo.size, Months[fd.fields.month-1], fd.fields.day, (fd.fields.year + 1980),
                    ft.fields.hours, ft.fields.minutes, fileinfo.name, directoryDelimiter, fileinfo.name );

        outputBufferIndex += rc;

      }

      findRc = _dos_findnext( &fileinfo );
      if ( findRc != 0 ) {
        closeFileinfo( );
      }

    }


    // If we are out of directory entries or if the output buffer has grown
    // large enough then send out what we have.

    if ( (outputBufferIndex > outputLimit) || (findRc) ) {

      if ( findRc != 0 ) {
        outputBufferIndex += sprintf( (char *)(outputBuffer + outputBufferIndex), "</pre></body></html>" );
      }

      if ( send( (uint8_t *)outputBuffer, outputBufferIndex ) == -1 ) return;

      // All bytes sent.  If we have more to send then point back to the beginning
      // of the buffer or we are going to have a bad time.

      outputBufferIndex = 0;
      break;
    }

  } // end directory loop


  if ( findRc  != 0) {

    // Finished.  We were too lazy to precompute the size of the output
    // or to use a chunked encoding so we have to close the socket.  The
    // call to setCloseWhenDone was already made for us when we got the
    // headers.  (And in Http09 force closed when done is the default.)

    setState( ReqDone );

  }

}



//-----------------------------------------------------------------------------
//
// Client::sendFile
//
// Unlike sendDirectory sendFile does not send its own headers.  This just
// strictly opens the file and shoves the bytes down the socket.  If headers
// are to be sent they will be sent before the initial call to this routine.
//
// We can't take the time to send entire files in one pass.  For small files
// that works great but for large files with multiple concurrent users you
// will cause timeouts.  Instead, design this to interleave with other active
// connections.
//
// Buffering strategy.  Use setvbuf to give the C runtime a larger buffer.
// Then read the bytes from the C runtime directly into our outgoing packet.
// This will result in full buffers going out all of the time.  When the C
// runtime buffer runs short it will read ahead a bit for us.  This is much
// easier than doing our own readahead and tracking how we consume that
// buffer.


// Data structure used to send packets.  1460 is the maximum payload for
// a normal TCP/IP packet with no options.  The sender has to remember that
// the other side might have an MSS less than this, or that the local MTU
// might be smaller than 1500.  And the remote window also has to be honored.

typedef struct {
  TcpBuffer b;
  uint8_t data[1460];
} DataBuf;


void Client::sendFile( void ) {

  if ( getState( ) == ReadRequest) {

    // This should not fail - we already stat'ed the file to get the size
    // and verified that it is a file.  But just in case, log it and kill
    // the client.

    fileHandle = fopen( fullPath, "rb" );

    // int lclErrno = errno;
    // TRACE_WARN(( "sendFile: opened handle is %p, errno: %u\n", fileHandle, lclErrno ));

    // Fixme: add a random error injection test for this

    if ( fileHandle == NULL ) {
      int lclErrno = errno;
      TRACE_WARN(( "Client::sendFile: file open error (%d) on %s\n", lclErrno, fullPath ));
      setState( ForceClose );
      return;
    }

    setvbuf( fileHandle, outputBuffer, _IOFBF, CLIENT_OUTPUT_BUFFER_SIZE );
    setState( Client::SendingFile );

  }


  TcpSocket *socket = getSocket();


  // We are filling raw transmit packets to cut out an extra memcpy or two,
  // but this is potentially dangerous because we have to honor the remote
  // window size ourselves. (The send() call handles that for us.)
  //
  // Record their remote window size before starting, and do not exceed it.
  uint16_t estRemoteWindow = socket->remoteWindow;

  uint16_t packetsSent = 0;
  uint8_t loopExitCode = 0;

  while ( 1 ) {

    PACKET_PROCESS_MULT(8);
    Arp::driveArp( );
    Tcp::drivePackets( );

    // Try to fill as large a packet as possible without violating the remote window.
    uint16_t maxBytesToSend = socket->maxEnqueueSize;
    if ( maxBytesToSend > estRemoteWindow ) {
      maxBytesToSend = estRemoteWindow;
    }

    // Update the estimated remote window.
    estRemoteWindow = estRemoteWindow - maxBytesToSend;

    // If we run out of room to enqueue packets or can't send a packet because the
    // estimated remote window has closed then stop sending data for now.  Also stop
    // after four packets so we can service other connections.
    if ( !(socket->outgoing.hasRoom( )) || (packetsSent > 4) || (maxBytesToSend == 0) ) {
      loopExitCode = 1;
      break;
    }

    DataBuf *buf = (DataBuf *)TcpBuffer::getXmitBuf( );
    if ( buf == NULL ) {
      loopExitCode = 1; 
      break;
    }

    uint16_t bytesToSend = fread( buf->data, 1, maxBytesToSend, fileHandle );

    //int e1 = errno;
    //int e2 = ferror( fileHandle );
    //TRACE_WARN(( "sendFile: handle: %p  bytesToSend: %u  errno: %u   ferror: %u\n", fileHandle, bytesToSend, e1, e2 ));

    if ( bytesToSend == 0 ) {

      TcpBuffer::returnXmitBuf( (TcpBuffer *)buf );

      if ( feof( fileHandle ) ) {
        loopExitCode = 2;
      }
      else if ( ferror( fileHandle ) ) {
        // This should be rare.
        int ec = ferror( fileHandle );
        TRACE_WARN(( "Client::sendFile: error reading file: %d %s\n", ec, fullPath ));
        loopExitCode = 3;
      }
      break;

    }
    else {
      buf->b.setDataLen( bytesToSend );
    }

    if ( socket->enqueue( &buf->b ) ) {
      // Socket error: they might have gone away on us.
      TcpBuffer::returnXmitBuf( (TcpBuffer *)buf );
      loopExitCode = 4;
      break;
    }

    packetsSent++;

  }


  // If we are done the client might be preserved for another request.
  // In case of an error we close the client early; they'll figure out
  // that we did not send all of the bytes that we promised.

  if ( loopExitCode == 2 ) {
    setState( Client::ReqDone );
    closeFileHandle( );
  }
  else if ( loopExitCode > 2 ) {
    closeFileHandle( );
    setState( SocketError );
  }

}


void Client::sendFileFromCache( uint16_t fileLen, uint8_t *fileBytes ) {

  if ( getState( ) == ReadRequest ) {
    setState( Client::SendingCachedFile );
    fileBytesPos = fileBytes;
    fileBytesRemaining = fileLen;
  }

  TcpSocket *socket = getSocket();

  // Record their remote window size before starting, and do not exceed it.
  uint16_t estRemoteWindow = socket->remoteWindow;

  uint16_t packetsSent = 0;
  uint8_t loopExitCode = 0;

  while ( 1 ) {

    // If we are out of bytes to send then leave happily and early ...
    if ( fileBytesRemaining == 0 ) {
      loopExitCode = 2;
      break;
    }

    PACKET_PROCESS_MULT(8);
    Arp::driveArp( );
    Tcp::drivePackets( );


    // Try to fill as large a packet as possible without violating the remote window.
    uint16_t maxBytesToSend = socket->maxEnqueueSize;
    if ( maxBytesToSend > estRemoteWindow ) {
      maxBytesToSend = estRemoteWindow;
    }

    // Update the estimated remote window.
    estRemoteWindow = estRemoteWindow - maxBytesToSend;


    // If we run out of room to enqueue packets or can't send a packet because the
    // estimated remote window has closed then stop sending data for now.  Also stop
    // after four packets so we can service other connections.
    if ( !(socket->outgoing.hasRoom( )) || (packetsSent > 4) || (maxBytesToSend == 0) ) {
      loopExitCode = 1;
      break;
    }


    // We are clear to send a packet.  Don't send more bytes than actually remain.
    if ( maxBytesToSend > fileBytesRemaining ) maxBytesToSend = fileBytesRemaining;


    DataBuf *buf = (DataBuf *)TcpBuffer::getXmitBuf( );
    if ( buf == NULL ) {
      loopExitCode = 1;
      break;
    }

    memcpy( buf->data, fileBytesPos, maxBytesToSend );
    fileBytesPos = fileBytesPos + maxBytesToSend;
    fileBytesRemaining = fileBytesRemaining - maxBytesToSend;

    buf->b.setDataLen( maxBytesToSend );

    if ( socket->enqueue( &buf->b ) ) {
      // Socket error: they might have gone away on us.
      TcpBuffer::returnXmitBuf( (TcpBuffer *)buf );
      loopExitCode = 3;
      break;
    }

    packetsSent++;

  }


  if ( loopExitCode == 2 ) {
    setState( Client::ReqDone );
  }
  else if ( loopExitCode > 2 ) {
    setState( SocketError );
  }

}




//-----------------------------------------------------------------------------
//
// Client::formatInternetDate
//
// Given a timestamp this will create a text string in the supplied buffer as
// per the RFC.  If you pass in too small of a buffer no damage will be done
// but the date will not be of the correct format.

int Client::formatInternetDate( char *buffer, int bufferLen, const char *headerName, time_t timestamp_p ) {

  time_t timestamp = timestamp_p;
  if ( timestamp == 0 ) timestamp = time( NULL );

  struct tm tmbuf;
  _gmtime( &timestamp, &tmbuf );

  int rc = snprintf( buffer, bufferLen, "%s: %s, %02d %s %04d %02d:%02d:%02d GMT" CRLF, 
                    headerName,
                    Days[ tmbuf.tm_wday ], tmbuf.tm_mday, Months[ tmbuf.tm_mon ], tmbuf.tm_year + 1900,
                    tmbuf.tm_hour, tmbuf.tm_min, tmbuf.tm_sec );

  #ifdef HTTPSRV_CONSISTENCY_CHECK
  assert( rc < bufferLen );
  #endif

  if ( rc > bufferLen ) rc = bufferLen;

  return rc;
}


//-----------------------------------------------------------------------------
//
// Client::getCloseHeader
//
// This method returns a pointer to a static string to use when the client
// is sending headers back.  As a side effect the method also determines if
// the socket is to be closed or if we can keep it alive.  Factors include
// the HTTP version in use, resources, and did we do something where we
// specifically need to force the client closed.
//
// Http09 is not handled by this method.  There are no headers in Http09
// and the required action is always close.
//
// If we need this client forced closed or we have no clients available
// for future incoming sockets then force this client closed.  Otherwise
// this client might sit and idle sucking up resources that we need
// elsewhere.
//
// We used to check to see if there was actually a socket waiting to get in.
// Don't do that - just close this client if there are no other clients
// available.  Otherwise, you might wind up leaving this client open because
// there are no sockets waiting but then a new socket will be forced to wait
// while an idle one gets cleaned up.

static const char *HttpHeaderConnClose = "Connection: close" CRLF;
static const char *HttpHeaderKeepAlive = "Connection: keep-alive" CRLF;
static const char *NullStr = "";

const char *Client::getCloseHeader( bool forceClosed ) {

  const char *rc = NullStr;

  if ( httpRequest.httpVer == Request::Http10 ) {

    // Keepalive was an extension to Http10 and it might not be present.

    if ( httpRequest.getKeepAliveState( ) == Request::KeepAlive ) {

      if ( forceClosed || (!Client::areClientsAvailable( )) ) {
        rc = HttpHeaderConnClose;
        setCloseWhenDone( );
      }
      else {
        rc = HttpHeaderKeepAlive;
      }

    }

    else if ( httpRequest.getKeepAliveState( ) == Request::NoKeepAlive ) {
      rc = HttpHeaderConnClose;
      setCloseWhenDone( );
    }

    else {
      // The default is to close.  Since Keepalive is an extension if the
      // client did not send a keepalive or close header then don't send
      // one back.  (rc is already set up above to NullStr.)
      setCloseWhenDone( );
    }

  }
  else if ( httpRequest.httpVer == Request::Http11 ) {

    if ( (httpRequest.getKeepAliveState( ) == Request::KeepAlive) ||
         (httpRequest.getKeepAliveState( ) == Request::DefaultKeepAlive) ) {

      // Requested keepalive or assumed default (which is keepalive) - can we accomodate?

      if ( forceClosed || (!Client::areClientsAvailable( )) ) {
        rc = HttpHeaderConnClose;
        setCloseWhenDone( );
      }
      else {
        rc = HttpHeaderKeepAlive;
      }

    }

    else {  // Only choice left is NoKeepAlive
      rc = HttpHeaderConnClose;
      setCloseWhenDone( );
    }

  }

  return rc;
}


static const char ContentEncoding_GZipped[] = "Content-Encoding: gzip" CRLF;
static const char TransferEncoding_Chunked[] = "Transfer-encoding: chunked" CRLF;
static const char CacheControl_NoCache[] = "Cache-Control: no-cache, no-store, must-revalidate" CRLF;


// If this returns anything except zero there was an error and the caller
// should just give up.  If we overflowed the headers are are going to
// close the connection and if there was a send error the client is already
// gone.

uint8_t Client::sendHeaders( uint16_t httpRc, const char *httpRcString,
                          bool forceClose, bool gzipped,
                          bool chunked, bool doNotCache,
                          uint32_t contentLength,
                          const char *contentType,
                          ExpiresHeaderOption expires,
                          const char *optionalString,
                          const char *callerName ) {

  // Setup optional strings. If they are not needed nothing will appear in the sent headers.

  const char *contentEncodingString = NullStr;
  if ( gzipped ) { contentEncodingString = ContentEncoding_GZipped; }

  const char *chunkedString = NullStr;
  if ( chunked ) { chunkedString = TransferEncoding_Chunked; }

  const char *cacheControlString = NullStr;
  if ( doNotCache ) { cacheControlString = CacheControl_NoCache; }

  if ( optionalString == NULL ) optionalString = NullStr;


  // We are using this client's outputBuffer.  The rule is you can't start filling the
  // outputBuffer until the headers are sent.

  char *nextPos = outputBuffer;
  int bytesLeft = CLIENT_OUTPUT_BUFFER_SIZE;

  while ( 1 ) {

    int rc = snprintf( nextPos, bytesLeft,
                       "%s %u %s" CRLF
                       "Server: mTCP HTTPServ (www.brutman.com/mTCP) " __DATE__ CRLF
                       "%s"
                       "%s"
                       "%s",
                       getHttpVersionString( ), httpRc, httpRcString,
                       contentEncodingString,
                       chunkedString,
                       cacheControlString
                     );

    nextPos += rc; bytesLeft -= rc; if ( bytesLeft < 0  ) break;

    rc = formatInternetDate( nextPos, bytesLeft, "Date", 0 );
    nextPos += rc; bytesLeft -= rc; if ( bytesLeft < 0  ) break;

    if ( contentType && contentType[0] ) {
      rc = snprintf( nextPos, bytesLeft, "Content-Type: %s" CRLF, contentType );
      nextPos += rc; bytesLeft -= rc; if ( bytesLeft < 0  ) break;
    }


    // Never send contentLength on a HEAD method.
    if ( contentLength && (httpRequest.getHttpMethod( ) == Request::GET) ) {
      rc = snprintf( nextPos, bytesLeft, "Content-Length: %lu" CRLF, contentLength ); 
      nextPos += rc; bytesLeft -= rc; if ( bytesLeft < 0  ) break;
    }

    if ( expires != Expires_DoNotSend ) {

      time_t expiresTime = time( NULL );

      if ( expires == Expires_5Minutes ) {
        expiresTime += 300ul;       // 5 minutes
      } else {
        expiresTime += Content_Long_Expires_Time;
      }

      rc = formatInternetDate( nextPos, bytesLeft, "Expires", expiresTime );
      nextPos += rc; bytesLeft -= rc; if ( bytesLeft < 0  ) break;

    }

    rc = snprintf( nextPos, bytesLeft, "%s%s" CRLF, optionalString, getCloseHeader( forceClose ) );
    nextPos += rc; bytesLeft -= rc;

    break;
  }

  if ( bytesLeft < 0 ) {
    TRACE_WARN(( "%s: headers overflowed\n", callerName ));
    send500InternalError( );
    return 1;
  }

  // This is the socket level send; it will do the right thing and persist
  // until all of the requested data is sent.
  if ( send( (uint8_t *)outputBuffer, (CLIENT_OUTPUT_BUFFER_SIZE - bytesLeft) ) == -1 ) return 1;

  return 0;
}
