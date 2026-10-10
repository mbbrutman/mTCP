/*

   mTCP HTTPServ FCache.h
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


   Description: File cache header file for the http server.

*/


#ifndef _FCACHE_H
#define _FCACHE_H


#include <stdio.h>

#include "types.h"

#include "httpserv.h"
#include "client.h"




// FileCache
//
// System sizes and speeds vary and we don't want to build a super-
// sophisticated caching system, especially considering how easy it is
// to fragment DOS memory.  This simple caching system lets a user directly
// tell the server what to cache in memory using a special URL and
// parameters to it.
//
// This is not space efficient but just keep a mapping of full path names to
// file cache information.  The path names should be the real names that
// URLS resolve to, so that multiple urls mapping to the same thing are
// all covered.
//
// What should one cache?  Any common files that get loaded by all pages
// like CSS files.  The root page.  And text files that are commonly used.
// Most clients handle gzipped content so cache the gzipped versions of files
// if available and ignore the non-gzipped versions.  (Primitive clients
// that do not support gzipping probably are not speed sensitive.)
//
//
// Other design notes:
//
// TreeNode would be a nice place to store cache information but we
// designed it to be very compact and readily blown away if it gets full.
// That works because it can always re-read state from disk.  Dynamically
// adding file cache information to that would screw that design up, so
// file caching information should be kept separate.


class FileCache {

  public:

    typedef struct {
      char     fileName[DOS_MAX_PATH_LENGTH];
      bool     gzipped;
      uint16_t fileSize;
      time_t   fileTime;
      uint8_t *filePointer;
    } CacheRec_t;

    static inline void setClearCache( void ) { clearRequested = true; };

    static inline bool isCacheClearRequested( void ) { return clearRequested; }

    static inline int8_t   getFilesCached( void ) { return filesCached; }
    static inline uint32_t getTotalBytesCached( void ) { return totalBytesCached; }

    static void   handleCommand( Client *target );
    static int8_t searchCache( const char *fullPath );
    static void   clearCache( void );

    static CacheRec_t *getEntry( int8_t index ) { return &directory[index]; }


    // Statistics

    static uint32_t   cacheHits;
    static uint32_t   filesServed;


  private:

    static void    addToCache( Client *target, char *filename );
    static void    showCache( Client *target );
    static void    doClearCache( Client *target );

    static uint8_t addToCache_private( const char *fullPath );
    static void    sendReturnCodeMessage( Client *target );
    
    static CacheRec_t directory[];
    static int8_t     filesCached;
    static bool       clearRequested;
    static uint32_t   totalBytesCached;


    static const char *addToCacheMessages[];

    static const char genericCacheResponseMsg[];

};


#endif
