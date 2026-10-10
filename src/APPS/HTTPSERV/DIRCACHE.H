/*

   mTCP HTTPServ DirCache.H
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


   Description: DirCache header file for the http server.

*/


#ifndef _DIRCACHE_H
#define _DIRCACHE_H


#include "httpserv.h"

#include "utils.h"



// TreeNode
//
// TreeNode implements the directory and name mapping cache.
//
// Caching notes
//
// The cache is limited in size and is preallocated up front.  The amount
// of data in the cache grows when new directories are examined during the
// path walking process.  If the size of the cache is exceeded the entire
// cache is flushed and the operation is retried again.  This seems cruel
// and unusual, but we do not have a good way  to deal with memory
// fragmentation.
//
// The cache does not use new or malloc; it has its own memory manager.  The
// memory manager only hands memory out; there is no way to return memory.
// It is assumed that any failure to get new memory requires the cache to be
// flushed; anything that gets a memory failure expects this.  The operation
// is then retried and it should complete because there will be plenty of
// free memory.  In the case where the retry fails an error will be surfaced
// to the user; the path is too long or there are too many mappings along the
// way that need to be cached.
//
// Flushing the cache is very easy; just reset the pointers to the start
// of the cache area.  And don't reuse any previous pointers. :-)  Rebuilding
// the root node from scratch throws away any pointers.  Be sure you don't
// try to reuse pointers you have on the stack.  (I said memory errors are
// fatal, right?  I meant it.)
//
//
// Root and root name handling
//
// TreeNode has a static root.  The static root must consist of a drive letter
// and colon with optional subdirectories, but no trailing slash.  That is
// because any path from the user that we are asked to walk will have a leading
// slash.
//
// Each node of the tree is a directory.  Each node stores its own name, which
// is in 8.3 format.  The only exception is the root of the tree, which might
// be a directory deep down a file path.  The root is special so the object
// will have "" for the name but the full path will be stored in a static
// string.
//
//
// Memory usage:
//
//  - Each tree node requires 30 bytes (no map or subdirs)
//  - Each subdirectory in a node requires up to 18 bytes (13 for the name, 4 for the pointer)
//  - The map depends on the number of entries and their lengths.
//
// Example:
//
//   Root node has 20 subdirectories, and each of those has 5 subdirectories
//
//   Level 0: Root node = 30 + (20 * 18) = 390 bytes
//   Level 1: 20 first level subdirectories = 20 * ( 30 + (5 * 18) ) = 2400 bytes
//   Level 2: 20 * ( 30 ) = 1800 bytes
//   Total: 4590 bytes
//
// So that is 121 different directories ... and you can have buckets of files in each one.
// Space is only used if you actually touch a directory so it is better to segregate low use
// files into a separate directories.
//
// If you start adding mappings to each one it gets more expensive quickly.
// The long name and DOS name have to be stored for each map entry.


class TreeNode {

  public:

    enum WalkStatus {
      Directory,        // The path resolves to a directory.
      DirectoryRedir,   // The path resolves to a directory but without a trailing slash
      PossibleFile,     // The path resolves to something that might be a file.
      BadPath,          // The path is bad and should feel bad.
      InternalError,    // Surface a processing error to the caller
      NeedsAuth,        // This resource needs authentication; send back a challenge
      Forbidden,        // Sorry Charlie
      GenStatusPage,    // Target is the generated status page
      GenClientsPage,   // Target is the generated clients page
      GenServerQuit,    // Kill the server
      GenCacheCmds,     // Cache a file
      FlushCache        // Internal to TreeNode: flush the cache and try again.
    };

    static int8_t     init( uint16_t size, const char *path );
    static WalkStatus walkPath( const char *path, const char *authUser, const char *authPass, char *realPath, bool skipAuth );

    static inline void setCacheFlushRequested( void ) { cacheFlushRequested = true; }
    static inline bool isCacheFlushRequested( void ) { return cacheFlushRequested; }
    static        void flushCache( void );


    // Statistics
    static inline uint16_t getNodeCount( void ) { return nodeCount; }
    static inline uint16_t getCacheFlushes( void ) { return cacheFlushes; }
    static inline uint16_t cacheUsed( void ) { return bytesAllocated; }
    static inline uint16_t cacheFree( void ) { return arenaSize - bytesAllocated; }

    static inline const char *getRootPath( void ) { return rootName; }


    // This is gross but this is used to communicate back to the main thread
    // if BASIC AUTH is needed for a file or directory.  It is safe because
    // we are single threaded between the time we walk the URI and send the
    // AUTH needed response.
    static char tmpRealm[52];


  private:

    char      *nameMap;         // Pairs of from/to names

    char      *dirMap;          // List of directory names
    TreeNode  *(*dirPtrs)[];    // Pointers to directories
    uint16_t   directories;     // Number of directories

    char      *authMap;         // List of files needing auth and their credentials
    char      *generatedMap;    // List of names for generated content

    char      *directoryIndex;  // File to display if the directory is the target
    int8_t    indexAllowed;     // -1 (use default), 0 = no, 1 = yes
    bool      indexHtmPresent;  // Is index.html in this directory?
    uint8_t   pad;

    // Name of this node (except for the root node, which is longer.)
    // This is not actually used and is only needed for debugging purposes.
    // A good consistency check would compare this to the directory name we
    // just think we walked into to ensure we are in the correct spot.
    char      myName[13]; 

    #ifdef HTTPSRV_CHECK_DIRCACHE
    uint16_t   nameMapEntries;  // Number of from/to pairs
    uint16_t   authMapEntries;  // Number of auth map entries
    uint16_t   genMapEntries;   // Number of generated map entries
    #endif


    // Statics for the class

    static TreeNode  rootOfEvil;                           // Root node
    static char      rootName[ DOS_MAX_PATHFILE_LENGTH ];  // Full root path

    static uint16_t  nodeCount;        // Statistics - number of nodes in the cache
    static uint16_t  cacheFlushes;     // Statistics

    static void     *arena;            // Start of our preallocated memory area
    static void     *nextMalloc;       // Next byte of memory to hand out
    static uint16_t  arenaSize;    ;   // Maxmimum allocation size
    static uint16_t  bytesAllocated;   // How many bytes have we handed out
    static void     *flushCkp;         // Where to move nextMalloc back to after a flush

    static char filename[ DOS_MAX_PATHFILE_LENGTH ];  // Temp storage for anybody to use

    static bool cacheFlushRequested;


    // Private methods

    int8_t initNode( const char *path, const char *name );
    int8_t readNameMap( const char *path );
    int8_t scanForDirectories( const char *path );
    void   doMapping( char *component );

    bool   hasAuthMap( void ) { return authMap != NULL; }
    bool   hasGeneratedMap( void ) { return generatedMap != NULL; }

    int8_t checkAuth( const char *authUser, const char *authPass, const char *component );

    WalkStatus generatedContentCheck( const char *component );

    void   displayNode( void );

    void zeroOutDirPointers( void );

    inline const char *getName( void ) const {
      if ( this == &rootOfEvil ) return rootName; else return myName;
    }


    // Private static methods

    static void *treeMalloc( uint16_t bytes );

    static WalkStatus walk_internal( const char *path, const char *authUser, const char *authPass, char *realPath, bool skipAuth );
};


#endif
