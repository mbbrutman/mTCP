/*

   mTCP HTTPServ FCache.cpp
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


   Description: File caching functions for the http server.

*/


#include <io.h>
#include <malloc.h>
#include <string.h>


#include "fcache.h"
#include "dircache.h"
#include "screen.h"




// Storage for our class variables
//

FileCache::CacheRec_t FileCache::directory[FILE_CACHE_MAX_ENTRIES];
int8_t                FileCache::filesCached = 0;
bool                  FileCache::clearRequested = false;
uint32_t              FileCache::totalBytesCached = 0;


// Statistics

uint32_t FileCache::cacheHits = 0;
uint32_t FileCache::filesServed = 0;


// Private storage areas for parsing query parameters.  The parameter could
// be a long URL so pick a reasonable length.

#define SCRATCH_PARM_NAME_LEN (20)
#define SCRATCH_PARM_VALUE_LEN (HTTP_REQUEST_URI_SIZE)

static char parameterName[SCRATCH_PARM_NAME_LEN];
static char parameterValue[DOS_MAX_PATHFILE_LENGTH];



// This is a very small local buffer so that you can give the user
// a return code, but not much more.

static char tmpBuffer[ HTTP_REQUEST_URI_SIZE + 80 ];



//-----------------------------------------------------------------------------
//
// Public functions

void FileCache::handleCommand( Client *target ) {

  char *pos = Request::getNextParm( target->httpRequest.getURIParmString( ),
                                    parameterName, SCRATCH_PARM_NAME_LEN,
                                    parameterValue, SCRATCH_PARM_VALUE_LEN );

  bool unknownCmd = true;

  if ( stricmp( parameterName, "add" ) == 0 ) {
    addToCache( target, parameterValue );
  }
  else if ( stricmp( parameterName, "show" ) == 0 ) {
    showCache( target );
  }
  else if ( stricmp( parameterName, "clear" ) == 0 ) {
    doClearCache( target );
  }
  else {
    sprintf( tmpBuffer, "Unknown cache command: %s", parameterValue );
    sendReturnCodeMessage( target );
  }

}


int8_t FileCache::searchCache( const char *fullPath ) {

  int8_t rc = -1;

  for ( int i=0; i < filesCached; i++ ) {
    if ( stricmp( fullPath, directory[i].fileName ) == 0 ) {
      rc = i;
      break;
    }
  }

  return rc;
}


void FileCache::clearCache( void ) {

  for ( uint8_t i=0; i < filesCached; i++ ) {
    free( directory[i].filePointer );
  }

  _fheapmin( );

  filesCached = 0;
  clearRequested = false;
  totalBytesCached = 0;

  addToScreen( MSG_VERBOSE, "File cache cleared\n" );
}



//-----------------------------------------------------------------------------
//
// Command handlers


// FileCache::addToCache
//
// Given a URL add the real file to an in-memory cache.  If a zipped
// version of the file exists that will be cached instead.  (All modern
// clients will request zipped content, so it saves on memory footprint.)
//
// To avoid unpleasantness with malloc and segments files can only be
// cached if they are less than 64KB - 512 bytes in size.
//
// This function is a wrapper around the real function, which uses a lot
// of early returns.

const char *FileCache::addToCacheMessages[] = {
  "Added",
  "Cache full",
  "File not found",
  "File too big",
  "File already in cache",
  "Out of memory",
  "File read error",
  "Needs auth"
};


void FileCache::addToCache( Client *target, char *filename ) {

  int rc = addToCache_private( filename );

  addToScreen( MSG_VERBOSE, "addToCache: %s %s\n", parameterValue, addToCacheMessages[rc] );

  sprintf( tmpBuffer, "Filename: %s, Return code: %s", parameterValue, addToCacheMessages[rc] );
  sendReturnCodeMessage( target );

}


static char realPath[DOS_MAX_PATHFILE_LENGTH];

uint8_t FileCache::addToCache_private( const char *path ) {

  if ( filesCached == FILE_CACHE_MAX_ENTRIES ) return 1;

  // Walk the directory tree the same way we would if this was an incoming URL.
  // This uses our existing long name to DOS name mapping, which is nice for
  // the user interface.

  if ( TreeNode::walkPath( path, "", "", realPath, true ) != TreeNode::PossibleFile ) return 2;

  // Create a convenient alias
  CacheRec_t *newRec = &directory[filesCached];

  struct stat statbuf;
  int statRc = stat( realPath, &statbuf );

  uint32_t fileSize;

  if ( (statRc == 0) && S_ISREG(statbuf.st_mode) ) {

    // A non-compressed version exists.  Use its timestamp even if
    // we find a zipped version of it instead.

    strcpy( newRec->fileName, realPath );
    fileSize = statbuf.st_size;
    newRec->fileTime = statbuf.st_mtime;
    newRec->gzipped = false;

    // Is there a zipped version?  If so cache that instead to save on memory.
    // Most modern clients will requested zipped content.

    strcpy( realPath, HTTPZips );
    int skipLen = strlen( HTTPDocs );
    strcat( realPath, newRec->fileName + skipLen );

    statRc = stat( realPath, &statbuf );

    if ( (statRc == 0) && S_ISREG(statbuf.st_mode) ) {
      // A zipped version exists - use it.
      strcpy( newRec->fileName, realPath );
      fileSize = statbuf.st_size;
      newRec->gzipped = true;
    }

  }
  else {
    return 2;
  }

  // Is the file too big?
  if ( fileSize > 65024ul ) return 3;
  newRec->fileSize = fileSize;

  // Search the cache to see if we have this already.
  if ( searchCache( newRec->fileName ) != -1 ) return 4;

  newRec->filePointer = (uint8_t *)mTCP_malloc( newRec->fileSize, newRec->fileName );
  if ( newRec->filePointer == NULL ) return 5;

  uint8_t *filePos = newRec->filePointer;

  FILE *file = fopen( newRec->fileName, "rb" );
  if ( file == NULL ) return 6;

  uint16_t totalBytesRead = 0;
  while ( !feof(file) && !ferror(file) ) {
    uint16_t bytesRead = fread( filePos, 1, 8192, file );
    filePos += bytesRead;
    totalBytesRead += bytesRead;
  }

  fclose( file );

  if ( totalBytesRead != newRec->fileSize ) {
    free( newRec->filePointer );
    return 6;
  }

  strupr( newRec->fileName );
  totalBytesCached += newRec->fileSize;
  filesCached++;

  return 0;
}




// showCache
//
// Show the contents of the cache to the user

static const char ShowCache_part1[] =
  "<html>"
    "<head>"
      "<title>"
        "mTCP HTTPServ File cache"
      "</title>"
    "</head>"
    "<body>"
      "<h1>mTCP HTTPServ File cache</h1>"
      "<pre>";

static const char ShowCache_part2[] =
      "</pre>"
    "</body>"
  "</html>";

static const char ShowCache_NoFilesCached[] = "No files are cached.";

void FileCache::showCache( Client *target ) {

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

  char *outputBuffer = target->getOutputBuffer( );

  strcpy( outputBuffer, ShowCache_part1 );
  uint16_t contentBytes = sizeof( ShowCache_part1 ) - 1;

  if ( filesCached ) {

    for ( int i=0; i < filesCached; i++ ) {

      contentBytes += snprintf( (outputBuffer+contentBytes), (CLIENT_OUTPUT_BUFFER_SIZE-contentBytes),
                      "%5u %s %s<br>",
                      directory[i].fileSize,
                      directory[i].gzipped ? "gzipped" : "plain  ",
                      directory[i].fileName );

      if ( contentBytes > CLIENT_OUTPUT_BUFFER_SIZE ) {
        contentBytes = CLIENT_OUTPUT_BUFFER_SIZE;
        break;
      }

    }

    // Summary information

    contentBytes += snprintf( (outputBuffer+contentBytes), (CLIENT_OUTPUT_BUFFER_SIZE-contentBytes),
                              "<p>%u files cached, %lu bytes used, %lu cache hits, %lu files served from cache",
                              filesCached,
                              totalBytesCached,
                              cacheHits,
                              filesServed );

    if ( contentBytes > CLIENT_OUTPUT_BUFFER_SIZE ) {
      contentBytes = CLIENT_OUTPUT_BUFFER_SIZE;
    }

  } else {

    strcpy( (outputBuffer+contentBytes), ShowCache_NoFilesCached );
    contentBytes += sizeof(ShowCache_NoFilesCached) - 1;

  }

  contentBytes += snprintf( (outputBuffer+contentBytes), (CLIENT_OUTPUT_BUFFER_SIZE-contentBytes), ShowCache_part2 );

  if ( contentBytes > CLIENT_OUTPUT_BUFFER_SIZE ) {
    contentBytes = CLIENT_OUTPUT_BUFFER_SIZE;
  }

  if ( contentBytes == CLIENT_OUTPUT_BUFFER_SIZE ) {
    addToScreen( MSG_ERROR, "showCache: content may have overflowed.\n" );
  }

  if ( target->send( (uint8_t *)outputBuffer, contentBytes ) == -1 ) return;

  target->setState( Client::ReqDone );

}


void FileCache::doClearCache( Client *target ) {

  // You just can't go clobbering the cache - it might be in use.
  // Set a global flag that can be checked during the idle loop at
  // a time when we know no clients are active.

  setClearCache( );

  ObjectsServed++;


  strcpy( tmpBuffer, "The cache will be cleared the next time the server goes idle." );
  sendReturnCodeMessage( target );

}




// FileCache::sendReturnCodeMessage
//
// This is for small one or two line messages.  Assumes the message to send
// is in tmpBuffer.

static const char FileCache::genericCacheResponseMsg[] =
  "<html>"
    "<head>"
      "<title>"
        "mTCP HTTPServ Cache Commands"
      "</title>"
    "</head>"
    "<body>"
      "%s"
    "</body>"
  "</html>";

void FileCache::sendReturnCodeMessage( Client *target ) {

  ObjectsServed++;
  target->httpRequest.setResponseCode( 200 );

  // Nothing we are sending here should even remotely be in danger of causing a buffer overrun.

  uint16_t contentLen = strlen(FileCache::genericCacheResponseMsg) + strlen(tmpBuffer) - 2;

  if ( target->httpRequest.getHttpVersion() > Request::Http09 ) {
    if( target->sendHeaders( 200, "OK", false, false, false, true, contentLen, "text/html",
                             Client::Expires_Immediate, NULL, "addToCache" ) ) return;
  }

  // Headers are sent.  Now we can form the content.

  if ( target->httpRequest.getHttpMethod( ) == Request::GET ) {
    char *clientOutputBuffer = target->getOutputBuffer( );
    uint16_t outputLen = sprintf( clientOutputBuffer, genericCacheResponseMsg, tmpBuffer );
    if ( target->send( (uint8_t *)clientOutputBuffer, outputLen ) == -1 ) return;
  }

  target->setState( Client::ReqDone );

}

