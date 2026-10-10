/*

   mTCP HTTPServ Client.h
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


   Description: Client side header for the http server.

*/


#ifndef _CLIENT_H
#define _CLIENT_H


#include "types.h"
#include "tcp.h"

#include "httpserv.h"



// Client and Request initialization:
//
// Client and Request have a minimal constructor that just sets a magic value
// that indicates that the object was constructed but not explicitly
// initialized yet.  That allows us to detect a true double delete of an
// initialized object vs. the early delete of an object that is not
// initialized yet.  (That might happen if the program aborts early.)

#define CLIENT_UNINITIALIZED_COOKIE (0x4321)




// Request
//
// We try to parse the request object as the bytes are received so that we
// do not have to make multiple passes through it.  This means that until
// the end of the request is found the fields are not valid.
//
// Lifecycle:
//
// A request object is embedded inside of each Client object.
// The constructor is minimalist so it is guaranteed to run.  It just sets
// a magic value that indicates that the object has not been properly
// initialized yet.
//
// Proper initialization involves allocating a few buffers from the heap.
// If any of those buffers fail to be allocated then the initialization
// fails and returns a bad return code.  From that point forward the buffers
// are reused for the entire program and only freed when the program ends.

class Request {

  friend class Client;

  public:

    enum HttpRequestStringNums {
      Host,
      UserAgent,
      AcceptEncoding,
      Authorization,
      Referer,
      Connection,
      IfModifiedSince,
      LastString
    };

    enum ParseStatus {
      Incomplete,
      RequestOverflowed,
      Complete,
      UriTooLong,
      UriParmsTooLong,
      BadCharacters,
      GeneralParsingError,
      Blocked
    };

    enum HttpVer {
      Http09,       // Prehistoric
      Http10,       // Supports headers
      Http11        // Persistent connections, virtual host support
    };

    enum HttpMethod {
      NOTSET,
      GET,
      HEAD
    };

    enum KeepAliveState {
      DefaultKeepAlive,     // Use the default for the protocol in use
      NoKeepAlive,          // Client said no keepalive
      KeepAlive             // Client said to use keepalive
    };
      

    // Reset the request object after each use.
    void    reset( bool preserveUnusedBytes );


    // Read a request from the socket.  Re-entrant in case the full request was not in the receive buffer.
    int16_t readRequestBytes( TcpSocket *socket );

    inline ParseStatus parse( Client *c ) {
      // See if we can parse the request.  If there are no new bytes since we last
        // checked then don't bother.
      if ( newBytesToParse ) return parse2( c ); else return Incomplete;
    }


    // These are only valid after a request is parsed.  Probably should put some debug
    // traps in here to make sure they are not being called at other times.  May return
    // NULL if the field was not found in the request.

    inline HttpVer        getHttpVersion( void )     { return httpVer; }
    inline const char    *getHttpVersionStr( void )  { return HttpVersionStrings[ httpVer ]; }

    inline HttpMethod     getHttpMethod( void )      { return httpMethod; }
    inline bool           getGzipAccepted( void )    { return gzipAccepted; }
    inline KeepAliveState getKeepAliveState( void )  { return keepAliveState; }

    inline char    *getURIString( void )             { return uriString; }
    inline char    *getURIParmString( void )         { return uriParmString; }
    inline char    *getAuthUser( void )              { return authUser; }
    inline char    *getAuthPass( void )              { return authPass; }
    inline time_t   getIfModifiedSinceTime( void )   { return ifModifiedSinceTime; }

    inline char    *getHostString( void )            { return requestValues[Host]; }
    inline char    *getAgentString( void )           { return requestValues[UserAgent]; }
    inline char    *getEncodingString( void )        { return requestValues[AcceptEncoding]; }
    inline char    *getAuthString( void )            { return requestValues[Authorization]; }
    inline char    *getRefererString( void )         { return requestValues[Referer]; }
    inline char    *getConnectionString( void )      { return requestValues[Connection]; }
    inline char    *getIfModifiedSinceString( void ) { return requestValues[IfModifiedSince]; }

    inline char    *getGenericRequestValueString( HttpRequestStringNums s ) { return requestValues[s]; }

           void     setResponseCode( uint16_t rc );
    inline uint16_t getResponseCode( void )          { return httpRc; }

    static char *getNextParm( char *input, char *name, uint16_t nameLen, char *value, uint16_t valueLen );

    const static char *HttpRequestNames[];
    const static char *HttpVersionStrings[];
    const static char *HttpMethodStrings[];

  private:

    // Don't use the constructor directly.  Use the init method instead.
    inline Request( ) { buffer = (uint8_t *)CLIENT_UNINITIALIZED_COOKIE; };

    // The destructor will deallocate any memory owned by this object.
    ~Request( );

    // Used only once by the Client object at startup.  Allocates memory
    int8_t      init( void );

    void parseAuthorization( char *pos );
    void parseIfModifiedSince( char *pos );

    ParseStatus parse2( Client *c );  // Request parsing routine if new bytes are availabble

    static uint16_t removeDotSegments( char *buffer, int bufferLen );

    #ifdef HTTPSRV_CHECK_REQUEST_OBJ
    void        consistencyCheck( void );
    #else
    #define consistencyCheck( )
    #endif


    // These two are pointers to buffers allocated once at program startup and then
    // reused.  They must be examined and cleaned up by the destructor.

    uint8_t *buffer;
    char    *uriString;
    char    *uriParmString;


    // Auth stuff: parsed userid and password from Authorization header
    char    authUser[CLIENT_AUTH_MAX_USERID_LEN];
    char    authPass[CLIENT_AUTH_MAX_PASSWORD_LEN];


    // Request buffer and tracking variables for parsing.

    uint16_t   parseIndex;       // Where in the buffer does parsing continue from?
    uint16_t   bufferIndex;      // What is the current end of the buffer?
    bool       newBytesToParse;  // Did we receive new data since our last parse attempt?
    uint8_t    padding;


    // All of these point into the buffer or are NULL if not found.

    char *origUriString;
    char *requestValues[LastString];


    // Flags based on what we found

    HttpVer        httpVer;
    HttpMethod     httpMethod;
    KeepAliveState keepAliveState;
    bool           gzipAccepted;
    uint8_t        padding2;
    time_t         ifModifiedSinceTime;

    uint16_t       httpRc;
};



// Client
//
// An instance of Client wrappers a socket connection and includes room for
// an HTTP request and a file reading buffer.  The buffer space is expensive
// in terms of RAM so the number of clients should be minimal.  In the case
// where there are more connections than clients the additional sockets will
// be in accepted state and will be picked up when a client frees up.  If you
// value concurrency more then you can increase the number of clients, but
// concurrent clients just slow things down and cost more RAM.
//
// ForceWhenDone:
//
//   If we are low on resources we can close connections after each request
//   instead of holding them open.  Set this if you need to do that.

class Client {

  public:

    enum State {
      Inactive,          // This client object is not in use
      ReadRequest,       // Reading an HTTP request from the socket
      SendingFile,       // Sending a file in response to a request
      SendingCachedFile, // Sending a file from cache
      SendingDirectory,  // Sending a directory listing
      ReqDone,           // Finished serving; Client decides to either close or go back to ReadRequest
      SocketError,       // The socket is probably dead; the Client needs to close up
      ForceClose,        // Tell the client that they have to close up
      Closing            // Waiting for the socket close to complete
    };

    enum ExpiresHeaderOption {
      Expires_DoNotSend,
      Expires_Immediate,
      Expires_5Minutes,
      Expires_LongFuture
    };

    // The constructor is private.  Nobody should need to use it directly.
    // The destructor should be private too but Watcom does not seem to like that.

    // The destructor will deallocate any memory owned by this object.
    ~Client( );

    inline const char *getRemoteHostName( void ) { return remoteHostName; }

    inline const char *getHttpVersionString( void ) {
      return Request::HttpVersionStrings[httpRequest.getHttpVersion( )];
    }

    inline const char *getHttpMethodString( void ) {
      return Request::HttpMethodStrings[httpRequest.getHttpMethod( )];
    }

    inline State      getState( void )         { return state; }
    inline void       setState( State s )      { state = s; }
    inline void       close( void )            { state = Closing; socket->closeNonblocking( ); }

    inline bool       getCloseWhenDone( void ) { return forceCloseWhenDone; }
    inline void       setCloseWhenDone( void ) { forceCloseWhenDone = true; }

    inline TcpSocket *getSocket( void )        { return socket; }
    inline char      *getOutputBuffer( void )  { return outputBuffer; }

    inline int16_t    readRequestBytes( void ) { return httpRequest.readRequestBytes( socket ); }

    const char       *getCloseHeader( bool forceClosed );

    int formatInternetDate( char *buffer, int bufferLen, const char *headerName, time_t timestamp_p );

    void sendDirectory( void );
    void sendFile( void );
    void sendFileFromCache( uint16_t fileLen, uint8_t *fileBytes );

    void send301ForDirectory( void );
    void send401NeedsAuth( const char *realm );
    void send500InternalError( void );
    void sendHaiku( uint16_t code, bool forceClose );

    uint8_t sendHeaders( uint16_t httpRc,
                         const char *httpRcString,
                         bool forceClose,
                         bool gzipped,
                         bool chunked,
                         bool doNotCache,
                         uint32_t contentLength,
                         const char *contentType, 
                         ExpiresHeaderOption expires,
                         const char *optionalHeaders,
                         const char *callerName );

    // Used to send small amounts of data.
    int16_t send( uint8_t *userBuf, uint16_t userBufLen );

    #ifdef HTTPSRV_CHECK_CLIENT_OBJ
    void consistencyCheck( void );
    #else
    #define consistencyCheck( )
    #endif


    // Public data

    Request httpRequest;

    // Fixme: make private

    char       fullPath[DOS_MAX_PATHFILE_LENGTH];
    uint8_t    padding;


    // Class methods

    static int8_t  initClients( uint16_t maxClients );

    static Client *allocateNewClient( TcpSocket *newSocket );
    static void    releaseClient( Client *target );

    #ifndef HTTPSRV_CHECK_CLIENTS_TABLE

    static inline uint16_t  areClientsAvailable( void ) { return activeClients < allocatedClients; };
    static inline uint16_t  getActiveCount( void )      { return activeClients; };
    static inline Client   *getClient( int16_t index )  { return clientTableIndex[index]; };

    #else

    static uint16_t  areClientsAvailable( void );
    static uint16_t  getActiveCount( void );
    static Client   *getClient( int16_t index );

    #endif


  private:

    // Don't use the contructor directly.  Use the init method instead.
    inline Client( ) { outputBuffer = (char *)CLIENT_UNINITIALIZED_COOKIE; };

    // If a file handle was active close it
    inline void closeFileHandle( void ) {
      if ( fileHandle != NULL ) fclose( fileHandle ); fileHandle = NULL;
    }

    // Protect against doing _dos_findclose when not necessary by
    // using fileinfoActive as a flag to show when it is safe.
    inline void  closeFileinfo( void ) {
      if ( fileinfoActive ) _dos_findclose( &fileinfo ); fileinfoActive = false;
    }


    TcpSocket *socket;  // Socket this client is using; changes
    State      state;   // Current state of this client


    // Malloc'ed buffer used for file reads or for building up large amounts of output.
    // If using for output then outputBufferIndex tells you where to write next.

    char *     outputBuffer;       // Allocated once and persistent
    uint16_t   outputBufferIndex;


    // Transient fields used for sending files and directories

    FILE      *fileHandle;         // Used while sending a file

    uint8_t   *fileBytesPos;       // Position when sending a file from cache
    uint16_t   fileBytesRemaining; // Number of bytes left to send


    struct find_t fileinfo;        // Used while sending a directory: dos fileinfo structure
    uint16_t      findRc;          // Return code from the last call to dos_find*
    bool          fileinfoActive;  // Is the fileinfo struct in use?

    bool          forceCloseWhenDone;  // Default is false - try to keep things open


    // Misc fields

    char       remoteHostName[22];    // Cached value from socket to make logging easier



    // Class data

  public:
    static const char *States[];

  private:
    static uint16_t allocatedClients;
    static uint16_t activeClients;

    static Client   clientTable[];
    static Client  *clientTableIndex[];

};


#endif
