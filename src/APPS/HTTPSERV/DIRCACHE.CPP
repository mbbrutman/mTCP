/*

   mTCP HTTPServ DirCache.cpp
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


   Description: Directory caching functions for the http server.

*/


#include <assert.h>
#include <ctype.h>
#include <string.h>
#include <malloc.h>
#include <sys/stat.h>

#include "utils.h"

#include "HTTPServ.H"
#include "DirCache.H"
#include "screen.h"






//----------------------------------------------------------------------------
//
// Utility functions
//
// We do not allow the DOS wildcard characters; add them if needed


/* Ye olde way ...

   static char DosChars[] = "!@#$%^&()-_{}`'~";

   int isValidDosChar( char c ) {
     if ( isalnum( c ) || (c>127) ) return 1;
     for ( int i=0; i < (sizeof(DosChars) - 1); i++ ) {
       if ( c == DosChars[i] ) return 1;
     }
     return 0;
   }


   Ye better way - a pre-computed table that just reduces isValidDosChar
   to a byte read from a table and some bit shifting.

   Here is the code to generate the table:

   for ( int i=0; i < 256; i++ ) {
     if ( isValidDosChar(i) ) {
       int mapByte = i / 8;
       int mapBit = i % 8;
       map[mapByte] = map[mapByte] | (1<<mapBit);
     }
   }

*/

static uint8_t DosCharMap[] = {
  0x00, 0x00, 0x00, 0x00, 0xFA, 0x23, 0xFF, 0x03,
  0xFF, 0xFF, 0xFF, 0xC7, 0xFF, 0xFF, 0xFF, 0x6F,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

inline uint8_t isValidDosChar( char c ) {
  return ( DosCharMap[c>>3] & (1 << (c & 0x7)) );
}

static int isValidDosFilename( const char *filename ) {

  if (filename==NULL) return 0;

  // Special case - check for . and ..
  if ( strcmp( filename, "." ) == 0 || strcmp( filename, ".." ) == 0 ) return 1;

  int len = strlen(filename);

  if ( len == 0 ) return 0;

  if ( !isValidDosChar( filename[0] ) ) return 0;

  int i;
  for ( i=1; (i<8) && (i<len) ; i++ ) {
    if ( filename[i] == '.' ) break;
    if ( !isValidDosChar( filename[i] ) ) return 0;
  }

  if ( i == len ) return 1;

  if ( filename[i] != '.' ) return 0;

  i++;
  int j;
  for ( j=0; (j+i) < len; j++ ) {
    if ( !isValidDosChar( filename[j+i] ) ) return 0;
  }

  if ( j > 3 ) return 0;

  return 1;
}



//----------------------------------------------------------------------------

// Static storage for TreeNode

TreeNode  TreeNode::rootOfEvil;
char      TreeNode::rootName[ DOS_MAX_PATHFILE_LENGTH ];

uint16_t  TreeNode::nodeCount = 0;
uint16_t  TreeNode::cacheFlushes = 0;

void     *TreeNode::arena;
void     *TreeNode::nextMalloc;
uint16_t  TreeNode::arenaSize;
uint16_t  TreeNode::bytesAllocated;
void     *TreeNode::flushCkp;

char      TreeNode::filename[ DOS_MAX_PATHFILE_LENGTH ];

char      TreeNode::tmpRealm[52];

bool      TreeNode::cacheFlushRequested;


// TreeNode::init
//
// Create the cache and initialize the root of the tree within the cache.
// Returns 0 if good, -1 if bad.  Bad includes not enough memory, bad
// path format, path does not actually exist, or error creating the root
// node.  (That would usually be a memory error.)
//
// The input path should at least start with a drive letter and a colon.
// We will try to stat whatever is passed in and if that fails, then
// this fails too.

int8_t TreeNode::init( uint16_t size, const char *path ) {

  if ( size < 512 || size > 65500 ) return -1;

  // Basic error checking: we have a string, it is not too long, and it starts
  // with a drive letter.

  if ( (path == NULL) || (strlen(path) >= DOS_MAX_PATHFILE_LENGTH) ) return -1;
  if ( !isalpha(path[0]) || path[1] != ':' ) return -1;

  strcpy( rootName, path );


  // Allocate memory

  arenaSize = size;

  arena = mTCP_malloc( arenaSize, "HTTP_DirCache" );
  if ( arena == NULL ) return -1;

  nextMalloc = arena;
  bytesAllocated = 0;


  // Pass in a bogus name so that initNode does not try to jam a large root path into
  // a 12 byte field.  When retrieving the name use the method; it knows how to handle
  // the name field correctly.
  //
  // Any error here is fatal.  This covers memory allocation failures and parse errors.

  if ( rootOfEvil.initNode( rootName, "root" ) ) {
    free( arena );
    return -1;
  }

  flushCkp = nextMalloc;

  nodeCount = 1;

  return 0;
}



void *TreeNode::treeMalloc( uint16_t bytes ) {

  void *rc = NULL;

  if ( bytesAllocated + bytes < arenaSize ) {
    rc = nextMalloc;
    bytesAllocated += bytes;
    nextMalloc = ((char *)nextMalloc + bytes);
  }

  return rc;
}


void TreeNode::flushCache( void ) {

  cacheFlushRequested = false;
  cacheFlushes++;

  // This preserves the root node which should not need re-reading.  But we
  // have to null out all of the directory pointers now.  The directory names
  // and everything else are preserved but we just wiped out everything except
  // the root node so there can be no dangling pointers.

  nextMalloc = flushCkp;
  bytesAllocated = (uint8_t *)flushCkp - (uint8_t *)arena;


  // Should never fail - we've done this already and if the user finds a way to
  // delete the root from underneath this code they deserve what they get.

  rootOfEvil.initNode( rootName, "root" );

  nodeCount = 1;
}





// TreeNode::zeroOutDirPointers
//
// Very special use .. only during flushes and only against the root
// node.

void TreeNode::zeroOutDirPointers( void ) {

  #ifdef HTTPSRV_CHECK_DIRCACHE
  assert( this != NULL );
  assert( this == &rootOfEvil );
  #endif

  for ( uint16_t i=0; i < directories; i++ ) {
    (*dirPtrs)[i] = NULL;
  }

}
    


// TreeNode::scanForDirectories
//
// Pass in a fully qualified directory without a trailing slash.
// Do not pass in bad input.
//
// Returns 0 if all good, -1 if any error
//
// Directory information will be read and stored, but pointers to the
// directories will be NULL.

inline bool isSpecialDir( const char *path ) {
  if ( path[0] == '.' && (path[1] == 0 || (path[1] == '.' && path[2] == 0)) ) return true; else return false;
}

int8_t TreeNode::scanForDirectories( const char *path ) {

  #ifdef HTTPSRV_CHECK_DIRCACHE
  assert( this != NULL );
  #endif

  #ifdef HTTPSRV_CHECK_PARAMS
  assert( path != NULL );
  assert( *path != 0 );
  #endif

  // Construct the filename that we are going to use for the directory search.

  strcpy( filename, path );
  strcat( filename, "\\*.*" );

  // Make a first pass to find directories.  Just figure out how many bytes
  // of storage we need during this pass.

  struct find_t fileinfo;

  int bytesRequired = 0;

  uint16_t findRc = _dos_findfirst( filename, (_A_SUBDIR), &fileinfo );

  while ( findRc == 0 ) {
    if ( (fileinfo.attrib & _A_SUBDIR) && !isSpecialDir(fileinfo.name) ) {
      bytesRequired += strlen(fileinfo.name) + 1;
      directories++;
    }
    findRc = _dos_findnext( &fileinfo );
  }

  _dos_findclose( &fileinfo );

  if ( directories == 0 ) return 0;


  dirMap = (char *)treeMalloc( bytesRequired );
  dirPtrs = (TreeNode *(*)[])treeMalloc( directories * sizeof(TreeNode *) );
  if ( (dirMap == NULL) || (dirPtrs == NULL) ) {
    return -1;
  }

  // printf( "Allocated %d bytes for directory names, %d for pointers\n", bytesRequired, (directories * sizeof(TreeNode *) ) );

  directories = 0;

  char *dirMapPos = dirMap;

  findRc = _dos_findfirst( filename, (_A_SUBDIR), &fileinfo );

  while ( findRc == 0 ) {
    if ( (fileinfo.attrib & _A_SUBDIR) && !isSpecialDir(fileinfo.name) ) {
      strcpy( dirMapPos, fileinfo.name );
      dirMapPos += strlen(fileinfo.name) + 1;
      (*dirPtrs)[directories] = NULL;
      directories++;
    }
    findRc = _dos_findnext( &fileinfo );
  }

  _dos_findclose( &fileinfo );

  return 0;
}




void TreeNode::doMapping( char *component ) {

  #ifdef HTTPSRV_CHECK_PARAMS
  assert( component != NULL ); assert( *component );
  #endif

  if ( nameMap == NULL ) return;

  #ifdef HTTPSRV_CHECK_DIRCACHE
  assert( this != NULL );
  assert( nameMapEntries > 0 );
  uint16_t currentEntry = 0;
  #endif


  char *pos = nameMap;

  while ( *pos != 0 ) {

    #ifdef HTTPSRV_CHECK_DIRCACHE
    assert( currentEntry < nameMapEntries );
    #endif

    if ( strcmp( pos, component ) == 0 ) {
      pos = pos + strlen(pos) + 1;

      #ifdef HTTPSRV_CHECK_DIRCACHE
      assert( strlen(component) < HTTP_PATH_COMPONENT_LEN );
      #endif

      strcpy( component, pos );
      break;
    }
    else {
      // Skip to the next pair
      pos = pos + strlen(pos) + 1;
      pos = pos + strlen(pos) + 1;

      #ifdef HTTPSRV_CHECK_DIRCACHE
      currentEntry++;
      #endif
    }

  }

}



// TreeNode::checkAuth
//
// Check to see if a given component needs an authorization challenge sent
// or is already properly authorized.
//
// Components are assumed to be DOS filenames and are not case sensitive.
//
// Do not call this unless you know there is an authMap available.
//
// Returns 0 if no auth was needed; an authMap might exist but there is no
//           entry for this component in it.
//         1 if auth failed a challenge must be sent; the realm is sent back
//           in a static variable.
//         2 if auth was needed and passed

int8_t TreeNode::checkAuth( const char *authUser, const char *authPass, const char *component ) {

  #ifdef HTTPSRV_CHECK_DIRCACHE
  assert( this != NULL );
  #endif

  #ifdef HTTPSRV_CHECK_PARAMS
  assert( authUser != NULL );                          // May be empty, but not NULL
  assert( authPass != NULL );                          // May be empty, but not NULL
  assert( component != NULL ); assert( *component );   // Not empty or null
  assert( authMap != NULL );                           // Not allowed to call here if this is NULL
  assert( authMapEntries > 0 );                        // Better be non-zero.
  uint16_t currentEntry = 0;
  #endif

  int8_t rc = 0;

  char *pos = authMap;

  while ( *pos != 0 ) {

    #ifdef HTTPSRV_CHECK_DIRCACHE
    assert( currentEntry < authMapEntries );
    #endif

    uint16_t skip = strlen(pos) + 1;

    if ( stricmp( pos, component ) == 0 ) {

      // Found an entry in the auth map; assume the challenge fails.
      rc = 1;

      pos += skip;

      // Copy the realm in case we need it, then skip over it to the password.
      strcpy( tmpRealm, pos );

      // This returns the password followed by a list of userids
      pos = getRealmPassword( tmpRealm );

      if ( pos == NULL ) {
        addToScreen( MSG_ERROR, "Warning: %s is in a realm %s which is not defined in the realms file.\n", component, tmpRealm );
        break;
      }

      if ( *authPass ) {

        if ( strcmp( authPass, pos ) == 0 ) {

          // Password matches.  Skip the password and then scan the user list
          // to see if this user is authorized.
          pos = pos + strlen(pos) + 1;

          char tmpUser[CLIENT_AUTH_MAX_USERID_LEN];

          while ( pos != NULL ) {
            pos = Utils::getNextToken( pos, tmpUser, CLIENT_AUTH_MAX_USERID_LEN );
            if ( stricmp( authUser, tmpUser ) == 0 ) {
              rc = 2;
              break;
            }
          }

        }

      } // end if user supplied a password

      // We found our match and the outcome is known.  Time to go.
      break;

    } else {

      // Not a match; skip ahead
      pos += skip;
      pos += strlen(pos) + 1;

      #ifdef HTTPSRV_CHECK_DIRCACHE
      currentEntry++;
      #endif
    }
        
  }

  return rc;
}




TreeNode::WalkStatus TreeNode::generatedContentCheck( const char *component ) {

  #ifdef HTTPSRV_CHECK_DIRCACHE
  assert( this != NULL );
  assert( generatedMap != NULL );  // Not allowed to call here if this is NULL
  assert( genMapEntries > 0 );
  uint16_t currentEntry = 0;
  #endif

  #ifdef HTTPSRV_CHECK_PARAMS
  assert( component != NULL ); assert( *component ); // Not empty or null
  #endif

  WalkStatus rc = PossibleFile;

  char *pos = generatedMap;

  while ( *pos != 0 ) {

    #ifdef HTTPSRV_CHECK_DIRCACHE
    assert( currentEntry < genMapEntries );
    #endif

    if ( stricmp( pos, component ) == 0 ) {

      pos = pos + strlen(pos) + 1;

      if ( stricmp( pos, "serverstatus" ) == 0 ) {
        rc = GenStatusPage;
      } else if ( stricmp( pos, "clients" ) == 0 ) {
        rc = GenClientsPage;
      } else if ( stricmp( pos, "serverquit" ) == 0 ) {
        rc = GenServerQuit;
      } else if ( stricmp( pos, "cachecmds" ) == 0 ) {
        rc = GenCacheCmds;
      } else {
        addToScreen( MSG_ERROR, "Unknown generated content type for %s", component  );
        rc = InternalError;
      }

      break;

    } else {

      pos = pos + strlen(pos) + 1;
      pos = pos + strlen(pos) + 1;

      #ifdef HTTPSRV_CHECK_DIRCACHE
      currentEntry++;
      #endif
    }

  }

  return rc;
}



char lineBuffer[256];

// All of these are one byte bigger than needed so that we can detect
// overflow conditions.

static char fromName[HTTP_PATH_COMPONENT_LEN + 1];
static char toName[13 + 1];
static char realm[HTTP_AUTH_MAX_REALM_LEN + 1];



// TreeNode::readNameMap
//
// Read the options and maps for this node.
//
// This has gotten more complicated since the first pass when there was only
// a name map to worry about.  Some parse errors can be ignored but some
// might be fatal.  For example, if somebody is trying to password protect a
// file and has screwed up we can't run with no protection.  So besides memory
// errors we can pass back an InternalServerError which should block things
// like that.
//
// If you have a parse error you have to fail and exit during the first pass.
// No memory is allocated until the second pass so there will be nothing to
// clean up if there is an error in the first pass.
//
// By the second pass everything should be checked already and the only thing
// that might go wrong is running out of memory.  If that happens the cache
// gets flushed (all except for the root node) and we try again.
//
// Returns 0 if all good
//        -1 if a memory error
//        -2 if we can't safely parse and continue

int8_t TreeNode::readNameMap( const char *path ) {

  #ifdef HTTPSRV_CHECK_DIRCACHE
  assert( this != NULL );
  #endif

  #ifdef HTTPSRV_CHECK_PARAMS
  assert( path != NULL ); assert( *path );
  #endif

  // Construct the filename
  strcpy( filename, path );
  strcat( filename, "\\"HTACCESS_FILENAME );

  FILE *mapFile = fopen( filename, "r" );
  if ( mapFile == NULL ) {
    // Not satisfying but if there is no file there is no problem
    return 0;
  }

  int readNameMapRc = 0;

  // Pass one is for detecting parsing problems and figuring out storage space.
  // Pass two is for allocating memory and constructing maps.

  int pass = 0;
  uint16_t currentLineNumber = 0;

  uint16_t nameMapBytesRequired = 0, authBytesRequired = 0, generatedBytesRequired = 0;
  char *nextNameMapPosition = NULL, *nextAuthPosition = NULL, *nextGeneratedPosition = NULL;

  while ( (pass < 2) && (readNameMapRc == 0) ) {

    if ( pass == 1 ) {

      // Second pass - allocate memory for any maps that we need.
      // The maps need an extra byte at the end for a single NULL
      // char to tell us when to stop searching through them.

      if ( nameMapBytesRequired ) {
        nameMap = (char *)treeMalloc( nameMapBytesRequired + 1);
        if ( nameMap == NULL ) {
          readNameMapRc = -1;
          break;
        }
        nextNameMapPosition = nameMap;
      }

      if ( authBytesRequired ) {
        authMap = (char *)treeMalloc( authBytesRequired + 1);
        if ( authMap == NULL ) {
          readNameMapRc = -1;
          break;
        }
        nextAuthPosition = authMap;
      }

      if ( generatedBytesRequired ) {
        generatedMap = (char *)treeMalloc( generatedBytesRequired + 1);
        if ( generatedMap == NULL ) {
          readNameMapRc = -1;
          break;
        }
        nextGeneratedPosition = generatedMap;
      }

    }



    while ( !feof(mapFile) ) {


      char *rc = fgets( lineBuffer, 256, mapFile );
      if ( rc == NULL ) break;

      // fgets leaves the newline in the string if the buffer is big
      // enough.  If we do not have the newline then the line was too
      // long or was not properly terminated.

      {
        char lastChar = *lineBuffer;
        char *index = lineBuffer;
        while (*index) lastChar = *index++;
        if ( lastChar != '\n' ) {
          readNameMapRc = -2;
          break;
        }
      }

      currentLineNumber++;

      char command[20];

      char *nextTokenPtr = Utils::getNextToken( lineBuffer, command, 20 );

      if ( stricmp( command, "map" ) == 0 ) {

        nextTokenPtr = Utils::getNextToken( nextTokenPtr, fromName, (HTTP_PATH_COMPONENT_LEN+1) );
        Utils::getNextToken( nextTokenPtr, toName, 14 );

        int fromLen = strlen(fromName);
        int toLen = strlen(toName);

        if ( (*fromName) && (*toName) && (fromLen < HTTP_PATH_COMPONENT_LEN) && (toLen < 13) && (isValidDosFilename(toName)) ) {
          if ( pass == 0 ) {
            nameMapBytesRequired += fromLen + toLen + 2;
          }
          else {
            strcpy( nextNameMapPosition, fromName );
            nextNameMapPosition += fromLen + 1;
            strcpy( nextNameMapPosition, toName );
            nextNameMapPosition += toLen + 1;

            #ifdef HTTPSRV_CHECK_DIRCACHE
            nameMapEntries++;
            #endif
          }
        }
        else {
          readNameMapRc = -2;
          break;
        }

      }

      else if ( stricmp( command, "GeneratedPage" ) == 0 ) {

        // toName is actually the DOS 8.3 filename that will get mapped to a
        // generated function.

        nextTokenPtr = Utils::getNextToken( nextTokenPtr, toName, 14 );
        Utils::getNextToken( nextTokenPtr, fromName, (HTTP_PATH_COMPONENT_LEN+1) );

        int fromLen = strlen(fromName);
        int toLen = strlen(toName);

        if ( (*fromName) && (*toName) && (fromLen < HTTP_PATH_COMPONENT_LEN) && (toLen < 14) && (isValidDosFilename(toName)) ) {
          if ( pass == 0 ) {
            generatedBytesRequired += fromLen + toLen + 2;
          }
          else {
            strcpy( nextGeneratedPosition, toName );
            nextGeneratedPosition += toLen + 1;
            strcpy( nextGeneratedPosition, fromName );
            nextGeneratedPosition += fromLen + 1;

            #ifdef HTTPSRV_CHECK_DIRCACHE
            genMapEntries++;
            #endif
          }
        }
        else {
          readNameMapRc = -2;
          break;
        }

      }

      else if ( stricmp( command, "FileAuth" ) == 0 ) {

        nextTokenPtr = Utils::getNextToken( nextTokenPtr, toName, 14 );
        Utils::getNextToken( nextTokenPtr, realm, HTTP_AUTH_MAX_REALM_LEN + 1 );

        int toNameLen = strlen(toName);
        int realmLen = strlen(realm);

        if ( toNameLen && (toNameLen < 13) && realmLen && (realmLen < HTTP_AUTH_MAX_REALM_LEN) ) {

          if ( pass == 0 ) {
            authBytesRequired += toNameLen + 1 + realmLen + 1;
          }
          else {
            strcpy( nextAuthPosition, toName );        // filename
            nextAuthPosition += toNameLen + 1;
            strcpy( nextAuthPosition, realm );         // realm
            nextAuthPosition += realmLen + 1;

            #ifdef HTTPSRV_CHECK_DIRCACHE
            authMapEntries++;
            #endif
          }

        }
        else {
          readNameMapRc = -2;
          break;
        }

      }

      else if ( stricmp( command, "DirectoryIndex" ) == 0 ) {

        if ( pass == 0 ) {

          Utils::getNextToken( nextTokenPtr, fromName, (HTTP_PATH_COMPONENT_LEN+1) );
          int fromLen = strlen( fromName );

          if ( (fromLen > 0) && (fromLen < HTTP_PATH_COMPONENT_LEN) ) {
            directoryIndex = (char *)treeMalloc( fromLen + 1 );
            if ( directoryIndex == NULL ) {
              readNameMapRc = -1;
              break;
            }
            strcpy( directoryIndex, fromName );
          }
          else {
            readNameMapRc = -2;
            break;
          }

        }

      }

      else if ( stricmp( command, "IndexAllowed" ) == 0 ) {

        if ( pass == 0 ) {

          Utils::getNextToken( nextTokenPtr, toName, 13 );

          if ( stricmp( toName, "yes" ) == 0 ) {
            indexAllowed = 1;
          }
          else if ( stricmp( toName, "no" ) == 0 ) {
            indexAllowed = 0;
          }
          else {
            readNameMapRc = -2;
            break;
          }

        }

      }

    } // end while not feof

    // Reposition at the start
    fseek( mapFile, 0, 0 );

    pass++;

  }

  fclose( mapFile );



  // If a map has entries in it then set the very last byte to NULL to indicate
  // that the end of the map has been reached.

  if ( readNameMapRc == 0 ) {
    if ( nextNameMapPosition ) *nextNameMapPosition = 0;
    if ( nextAuthPosition ) *nextAuthPosition = 0;
    if ( nextGeneratedPosition ) *nextGeneratedPosition = 0;
  }
  else if ( readNameMapRc == -2 ) {
    if ( isScreenReady() ) {
      addToScreen( MSG_ERROR, "Parse error at line %u in %s\n", currentLineNumber, filename );
    } else {
      fprintf( stderr, "Parse error at line %u in %s\n", currentLineNumber, filename );
    }
  }

  return readNameMapRc;
}





// TreeNode::initNode
//
// A TreeNode represents a directory, caching the HTACCESS file,
// subdirectories and some other meta data.  This function initializes
// and sets the node for the specified directory, including reading
// the HTACCESS file and scanning the subdirectories.
//
// Path should be a path name without the trailing slash.
//
// Returns 0 if all good
//        -1 if a memory fail
//        -2 if a parse failure

int8_t TreeNode::initNode( const char *path, const char *name ) {

  #ifdef HTTPSRV_CHECK_DIRCACHE
  assert( this != NULL );
  #endif

  #ifdef HTTPSRV_CHECK_PARAMS
  assert( path != NULL ); assert( *path );
  assert( name != NULL ); assert( *name );
  #endif

  nameMap = NULL;

  dirMap = NULL;
  dirPtrs = NULL;
  directories = 0;

  authMap = NULL;

  generatedMap = NULL;

  #ifdef HTTPSRV_CHECK_DIRCACHE
  nameMapEntries = 0;
  authMapEntries = 0;
  #endif


  directoryIndex = NULL;
  indexHtmPresent = false;

  indexAllowed = -1;

  // Run some checks on the input to see if it is safe.  The path is never
  // going to be NULL or 0 length because we always have a root and that
  // was verified already.

  int len = strlen(path);
  if ( len >= (DOS_MAX_PATH_LENGTH-1) ) return -1;
  if ( path[len-1] == '\\' ) return -1;


  // Interesting piece of code here.  We only call this on things that are
  // directories, so why are we stating it again?  Worse, this fails if
  // it runs against a drive letter without a subdirectory.
  //
  // Commenting out for now.
  //
  // struct stat statbuf;
  // int rc = stat( path, &statbuf );
  // if ( (rc != 0) || (!S_ISDIR(statbuf.st_mode)) ) return -1;

  strcpy( myName, name );
  strupr( myName );

  // See if index.htm is present

  struct stat statbuf;
  strcpy( filename, path );
  strcat( filename, "\\index.htm" );
  int rc = stat( filename, &statbuf );
  if ( (rc == 0) && (S_ISREG(statbuf.st_mode)) ) { indexHtmPresent = true; }


  

  if ( scanForDirectories( path ) ) return -1;
  return readNameMap( path );
}




// TreeNode::walkPath
//
// Given a user path walks the path.  For each component:
//
// - Map to a new name (optional)
// - Verify the component is a valid DOS filename
// - Do authorization checks
//
// Inputs:
//  - Starts with a directory delimiter (either one)
//
//
// Returns:
//
//  Directory:      This is a valid directory in the directory chain.
//  DirectoryRedir: The user specified a directory but without the trailing
//                  directory delimeter, so they need to be redirected
//  PossibleFile:   This may be a valid file at the end of a valid directory chain
//  BadPath:        The directory chain was invalid, so the target is too.
//  InternalError:  Something went really wrong; results in a 500 to the user
//  NeedsAuth:      It looks valid, but the directory needs auth credentials
//  Forbidden:      Nope. Could refer to a auth or to not generating indexes for dirs.
//
//  Gen*: The user landed on something that triggers an action that is not
//        serving a page or a directory.
//
//  realPath is an output that includes everything DOS needs to stat or open
//  the final target, assuming that Invalid was not returned.
//
// The naive way to do this would be to walk each directory and read the HTACCESS
// file at each level.  That would be slow because of the hard drive accesses, and
// wasteful because you are doing the same things over and over again.  We use
// the TreeNode data structures here to cache that information and hopefully make
// this quick.

TreeNode::WalkStatus TreeNode::walkPath( const char *path, const char *authUser, const char *authPass, char *realPath, bool skipAuth ) {

  #ifdef HTTPSRV_CHECK_PARAMS
  assert( path != NULL );
  assert( *path != 0 );
  assert( authUser != NULL );
  assert( authPass != NULL );
  assert( realPath != NULL );
  #endif


  WalkStatus rc = walk_internal( path, authUser, authPass, realPath, skipAuth );

  if ( rc == FlushCache ) {

    // We did not have enough room in the cache to walk that path.  Flush the
    // cache out, rebuild the root node, and try again.

    flushCache( );

    rc = walk_internal( path, authUser, authPass, realPath, skipAuth );

    if ( rc == FlushCache ) {
      rc = InternalError;
      addToScreen( MSG_ERROR, "DirCache: not enough cache to process %s\n", path );
    }

  }

  strupr( realPath );
  return rc;
}





// walk_internal
//
// Given a URL walk through it, mapping long names to short names and checking
// authorization.  The walk stops when we hit a possible file or end with
// a directory.
//
// If the user specified a directory:
// - If it was not terminated with a / then indicate a redirect is needed
// - If there is a DirectoryIndex directive then append the target name, do
//   mapping, do an auth check on it, and return it as a possible file.
//   Since the user specified a target file do not fall back to constructing
//   and sending a directory listing dynamically.
// - If none of the above, append "index.htm", map it, do an auth check,
//   but return it as a possible directory index and not a possible file.
//   Because if it does not exist then we still want to decide if a
//   directory listing should be constructed or not.

TreeNode::WalkStatus TreeNode::walk_internal( const char *path, const char *authUser, const char *authPass, char *realPath, bool skipAuth ) {

  *realPath = 0;

  // Some quick error checking
  if ( (path == NULL) || ((*path != '/') && (*path != '\\')) ) return BadPath;

  // Skip leading / from the user
  const char *pos = path + 1;


  TreeNode *currentNode = &rootOfEvil;


  bool lastCharWasDelimiter = true;

  bool noMoreCheckAuth = skipAuth;


  // Always start by adding the name of the root to realPath.
  strcpy( realPath, getRootPath() );


  char component[HTTP_PATH_COMPONENT_LEN];

  while ( *pos ) {

    // Here at the top of the loop *pos is pointing at the next part of the
    // path to check, and the previous part was either the root directory
    // or a subdirectory.

    // Extract the next component.

    int i=0;
    while ( *pos && (*pos != '/' && *pos != '\\') ) {
      component[i] = *pos;
      pos++; i++;
    }
    component[i] = 0;


    // pos is either on the null char or a delimiter
    if ( *pos ) {
      lastCharWasDelimiter = true;
      pos++;
    } else {
      lastCharWasDelimiter = false;
    }


    // Is there a mapping from a long (case-sensitve) name to short DOS filename (not case-sensitive) ?
    currentNode->doMapping( component );

    // If we don't have a valid DOS filename by here we are done.
    if ( !isValidDosFilename( component ) ) { return BadPath; }

    // TRACE_WARN(( "Checking auth: %p %s:%s %s\n", currentNode, authUser, authPass, component ));

    // Remember, checkAuth is not case sensitive because it thinks it is checking
    // a DOS filename or directory.

    if ( (noMoreCheckAuth == false) && currentNode->hasAuthMap( ) ) { 
      int8_t checkAuthRc = currentNode->checkAuth( authUser, authPass, component );
      if ( checkAuthRc == 1 ) {
        return NeedsAuth;
      }
      else if ( checkAuthRc == 2 ) {
        noMoreCheckAuth = true;
      }
    }


    // See if this is one of our subdirectories.  If so, step into it and go
    // around again.  If not then it is a possible file or something invalid.


    char *dirMapPos = currentNode->dirMap;
    int j;
    for ( j=0; j < currentNode->directories; j++ ) {
      if ( stricmp( component, dirMapPos ) == 0 ) {
        break;
      }
      dirMapPos += strlen(dirMapPos) + 1;
    }


    if ( j == currentNode->directories ) {

      // Not in the directory list.  It might be a file.

      if ( (lastCharWasDelimiter == false) && (stricmp( component, HTACCESS_FILENAME ) != 0) ) {

        // Great, it looks like a file and it is not HTACCESS.---.
        // Add it to the path we are building up and try to serve it.

        strcat( realPath, "\\" );
        strcat( realPath, component );

        if ( currentNode->hasGeneratedMap( ) ) {
          return currentNode->generatedContentCheck( component );
        }
        else {
          return PossibleFile;
        }

      }

      // We don't like files that have trailing slashes or look like
      // our htaccess files.
      return BadPath;

    }


    // It is one of our subdirectories.

    strcat( realPath, "\\" );
    strcat( realPath, component );

    if ( (*(currentNode->dirPtrs))[j] != NULL ) {

      currentNode = (*(currentNode->dirPtrs))[j];

      #ifdef HTTPSRV_CHECK_DIRCACHE
      assert( stricmp(currentNode->myName, component) == 0 );
      #endif

    }
    else {

      // Build the TreeNode and process the HTACCESS file for this directory.

      TreeNode *tmpNode = (TreeNode *)treeMalloc( sizeof(TreeNode) );

      if (tmpNode == NULL ) {
        return FlushCache;  // Whoops, out of cache memory.  This will force a retry.
      }
      else {

        int initNodeRc = tmpNode->initNode( realPath, component );
        if ( initNodeRc == -1 ) {
          return FlushCache;  // Whoops, out of memory again.  This will force a retry.
        }
        else if ( initNodeRc == -2 ) {
          return InternalError;  // Something went wrong.  This will return a 500 to the user.
        }
        else {
          nodeCount++;
          (*(currentNode->dirPtrs))[j] = tmpNode;
          currentNode = tmpNode;
        }
      }

    } // end else create a new node

  }



  // If you get here it was because you ran out of path components to check
  // and the last thing specified was a directory.  If anything else happened,
  // do an early return instead of going through here.

  // If they specified a directory but did not have the trailing '/' then
  // send them a redirect.

  if ( lastCharWasDelimiter == false ) { return DirectoryRedir; }


  // Did they use the DirectoryIndex directive? If so it may need mapping.
  // If not, then use index.htm which never needs mapping.

  if ( currentNode->directoryIndex ) {

    strcpy( component, currentNode->directoryIndex );
    currentNode->doMapping( component );

    // By this point it should be a valid DOS filename.
    if ( !isValidDosFilename( component ) ) { return BadPath; }

  } else {

    if ( currentNode->indexHtmPresent ) {

      strcpy( component, "index.htm" );

    } else {

      // If this directory doesn't specify indexing allowed explictly then
      // use the global default.  Otherwise, do what it says.
      if ( currentNode->indexAllowed == -1 ) {
        return DirectoryIndexingAllowedDefault ? Directory : Forbidden;
      }
      else {
        return currentNode->indexAllowed ? Directory : Forbidden;
      }

    }

  }


  // Auth check

  if ( (noMoreCheckAuth == false) && currentNode->hasAuthMap( ) ) { 
    int8_t checkAuthRc = currentNode->checkAuth( authUser, authPass, component );
    if ( checkAuthRc == 1 ) { return NeedsAuth; }
  }

  // Auth checks have passed.  If it exists serve it.  (We will know if
  // index.htm exists but not if a user specified index file exists.)

  strcat( realPath, "\\" );
  strcat( realPath, component );

  return PossibleFile;

}

