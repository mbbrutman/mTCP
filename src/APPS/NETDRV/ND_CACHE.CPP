/*

   mTCP NetDrive (ND_CACHE.CPP)
   Copyright (C) 2025-2026 Michael B. Brutman (mbbrutman@gmail.com)
   mTCP web page: http://www.brutman.com/mTCP/mTCP.html


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


   Description: A benchmark to test different read-ahead values.

   If the client waits for an explicit response for each command to the
   server then performance is limited by distance.  On a local network
   this is not much of an issue but across the Internet it becomes a
   problem very quickly.  For example, a 50ms round-trip time with 1KB
   payloads limits throughput to 20KB/sec, which is just above floppy
   drive speeds.

   The read-ahead feature tries to overcome the latency problem by
   sending packets ahead of when they are requested.  In a perfect
   world you want to send as many packets as you can, but we have old
   machines here that are limited on CPU or network card features, so
   flooding them with packets might result in packet loss.  Losing
   read-ahead packets is suboptimal, but accidentally losing the
   actual read response is very costly.

   This benchmark tries varying read-ahead values to see where the
   optimal setting is for a specific machine and server combination.
   Fast machines (high end 386 or better) probably don't need to
   limit the maximum read-ahead, but slower machines (XT class)
   will definitely need to limit read-ahead packets to avoid
   flooding the machine.


   Timing notes:

   I have desperately tried to use the BIOS tick timer to get accurate
   timings, but it just doesn't work - a very busy machine will start
   to drop timer interrupts, making it look like the benchmark is
   running faster than it really is.  After a lot of experimentation
   and thought I've decided to use the CMOS RTC as the time base
   because it is immune to the loss of the interrupts.

   The general problem is that the packet driver might be keeping
   interrupts disabled for too long.  And a lot of them will hook
   the timer interrupt too, so unless they are also checking for
   re-entrancy things will go badly.  NetDrive also hooks the timer
   interrupt to send ARP responses, but that path is safe with respect
   to the DOS entry points through the device driver and the receive
   routine through the packet driver.

*/


#include <dos.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "types.h"

#include "arp.h"

#include "shared.h"
#include "asminc.h"



// Do you have a PCjr with a JrIDE sidecar?  If so, you are in luck - we
// can use that as a timer too in addition to the standard PC AT CMOS RTC.

#define JRIDE_RTC_ADDR_PORT (0x70)
#define JRIDE_RTC_DATA_PORT (0x71)



// Command line parameters

int8_t   TargetDriveLetter = 0;    // A=0, B=1, C=2, ...
int      TestLen = 5;              // How long to test each iteration
int      cacheSizeKB = 0;          // Read-ahead parameter in KB
int      maxWriteParm = 32;        // Max write size paramter in KB
int      TimeSource = 0;           // 0 = PC AT CMOS clock, 1 = PCjr JrIDE, 2 = DOS
int      Operation = 0;


Net_data_t far *net_data;          // Shared NetDrive data structure
Unit_t far *curr_unit;             // Device driver unit specific data

uint8_t far *testBuffer;

uint8_t DOS_version_major;



void parseArgs( int argc, char *argv[] );
int  checkTimeSource( void );
void testDriver( int currentReadAhead );
int  runTrial(int cacheBlocks, int seconds, int msDelay, uint32_t *scaledRate);



// Triggered either by Ctrl-Break or an unrecoverable error.
volatile int EarlyExit = 0;

// Ctrl-Break and Ctrl-C handler.  Check the flag once in a while to see if
// the user wants out.

void __interrupt __far ctrlBreakHandler( ) {
  EarlyExit = 1;
}





// Signature to verify we have found the NetData structure in memory.
// The last two bytes are the major and minor revision numbers.
static const char Signature[] = {'N', 'E', 'T', 'D', 'R', 'I', 'V', 'E', 0x00, SHARED_DATA_VERSION};


static char *CopyrightMsg = "mTCP nd_cache by M Brutman (mbbrutman@gmail.com) (C)opyright 2026-2026\nVersion: " __DATE__ "\n\n";

int main( int argc, char *argv[] ) {

  printf( CopyrightMsg );

  parseArgs( argc, argv );

  if ( checkTimeSource( ) ) { exit( 1 ); }


  uint16_t dosv = dosVersion( );
  DOS_version_major = dosv & 0xff;

  typedef struct {
    Net_data_t far *net_data;
    Unit_t     far *unit;
  } ioctl_data_t;

  ioctl_data_t ioctl_data;

  // We need a far pointer to a far pointer that points at a Net_data_t structure.

  ioctl_data_t far **p = (ioctl_data_t far **)MK_FP(FP_SEG(&ioctl_data), FP_OFF(&ioctl_data));

  int rc = ioctl_read( TargetDriveLetter+1, sizeof(ioctl_data), p );
  if ( rc != sizeof(ioctl_data) ) {
    puts( "Error: Not a NetDrive device or wrong version." );
    exit(1);
  }

  // Copy the two pointers to globals for convenience.
  net_data = ioctl_data.net_data;
  curr_unit = ioctl_data.unit;

  // Look for our eye catcher before the NetData structure to verify
  // that we have found the driver and NetData structure.  This is more
  // than just an eye catcher; the major and minor version number are embedded
  // in it too.  At some point we'll need another error message for a version
  // mismatch.

  char far *v = ((char far *)net_data) - sizeof(Signature);
  bool match = true;
  for (int i=0; i<sizeof(Signature); i++) {
    if (v[i] != Signature[i]) match = false;
  }

  if (match == false) {
    puts( "Error: Version mismatch between this program and the NetDrive device driver." );
    exit(1);
  }

  if ( curr_unit->session == 0 ) {
    puts("A drive is not connected.");
    exit(1);
  }

  int currentReadAhead = curr_unit->max_readahead/2;

  printf( "NetDrive device opened, current read-ahead cache size is %d KB\n", currentReadAhead );


  if ( Operation == 1 ) {
    testDriver( currentReadAhead );
  }

  else if ( Operation == 2 ) {
    int currentReadAheadKB = curr_unit->max_readahead / 2;
    printf("ReadAhead was %dKB, setting to %dKB\n", currentReadAheadKB, cacheSizeKB);
    curr_unit->max_readahead = cacheSizeKB*2;
  }

  else if ( Operation == 3 ) {
    int currentMaxWriteSizeKB = curr_unit->max_write_size / 2;
    printf("Max write size was %uKB, setting to %uKB\n", currentMaxWriteSizeKB, maxWriteParm);
    curr_unit->max_write_size = maxWriteParm*2;

  }

  return 0;
}


// Do you have a PCjr with a JrIDE sidecar?  If so, you are in luck - we
// can use that as a timer too in addition to the standard PC AT CMOS RTC.

#define JRIDE_RTC_ADDR_PORT (0x70)
#define JRIDE_RTC_DATA_PORT (0x71)


int checkTimeSource( void ) {

  switch ( TimeSource ) {

    case 0: {
      if ( isCMOSClockPresent( ) == false ) {
        puts( "No CMOS clock detected." );
        return 1;
      }

      CMOSTime_t t;
      readCMOSTime( &t );
      if ( (t.hours > 23) || (t.minutes > 59) || (t.seconds > 59) ) {
        puts( "Your CMOS clock time looks to be corrupted." );
        return 1;
      }
      break;
    }

    case 1: {
      outPortB(JRIDE_RTC_ADDR_PORT, 0x00); // seconds
      unsigned seconds = inPortB(JRIDE_RTC_DATA_PORT);
      outPortB(JRIDE_RTC_ADDR_PORT, 0x02); // minutes
      unsigned minutes = inPortB(JRIDE_RTC_DATA_PORT);
      outPortB(JRIDE_RTC_ADDR_PORT, 0x04); // hours
      unsigned hours = inPortB(JRIDE_RTC_DATA_PORT);

      if ( (seconds > 59) || (minutes > 59) || (hours > 23) ) {
        puts( "Your JrIDE clock time looks to be corrupted." );
        return 1;
      }

      break;
    }

    case 2: {
      puts( "** Warning: DOS time can be inaccurate on this benchmark due to I/O load.\n"
            "Use the -ts option to use the CMOS clock if available or use a stopwatch.\n");
      break;
    }

  }

  return 0;
}


// Returns a number of seconds based on the current minute and seconds
// of the time source.  (That ranges from 0 to 3599.)
//
// If for some reason the CMOS clock can't be read after 3 attempts
// the program will terminate early.

uint16_t readSeconds( void ) {

  switch ( TimeSource ) {

    case 0: {
      CMOSTime_t t;
      for ( int i=0; i < 3; i++ ) {
        int rc = readCMOSTime( &t );
        if ( rc == 0 ) {
          return (t.minutes) * 60 + t.seconds;
          break;
        }
      }

      EarlyExit = 2;
      return 0;
    }

    case 1: {
      outPortB(JRIDE_RTC_ADDR_PORT, 0x00); // seconds
      unsigned seconds = inPortB(JRIDE_RTC_DATA_PORT);
      outPortB(JRIDE_RTC_ADDR_PORT, 0x02); // minutes
      unsigned minutes = inPortB(JRIDE_RTC_DATA_PORT);
      return (minutes*60) + seconds;
    }

    case 2: {
      struct dostime_t dosTime;
      _dos_gettime( &dosTime );
      return (dosTime.minute*60) + dosTime.second;
    }

  }

  // Keep the compiler happy
  return 0;
}


inline uint16_t getElapsedSeconds( uint16_t end, uint16_t start ) {
  if ( end < start ) { end += 3600; }
  return end - start;
}





  

void testDriver( int currentReadAhead ) {

  // While we can have up to 64KB of read-ahead, we only test up to 32KB.
  // Anything more doesn't really prove much, and if you run fine at 32KB
  // of read-ahead then you should just set it to 64KB.
  //
  // We need an extra 1KB for the actual read block, and then the read-ahead.
  testBuffer = (uint8_t far *)_fmalloc(34*1024);
  if ( testBuffer == NULL ) {
    puts("Error allocating memory.");
    exit(1);
  }

  // Hook the Ctrl-Break and Ctrl-C handlers now, and don't exit the program
  // without undoing these.

  void (__interrupt __far *oldCtrlBreakHandler)( ) = getvect( 0x1b );
  setvect( 0x1b, ctrlBreakHandler );
  setvect( 0x23, ctrlBreakHandler );

  printf("\nRunning trials for %d seconds, use Ctrl-Break to stop early.\n", TestLen );
  printf("A ** after a measurement indicates a new best speed.\n\n" );
  fflush( NULL );

  uint32_t bestScaledRate = 0;

  for ( int i=0; i < 33; i++ ) {

    if ( EarlyExit ) break;

    // Change 2 to 10 if you want to experiment with delays between packets.
    // Also change the corresponding printf below.
    int msDelay = 0;
    while ( msDelay < 2 ) {

      if ( EarlyExit ) break;

      uint32_t scaledRate;
      int rc = runTrial(i, TestLen, msDelay, &scaledRate);
      if ( (rc == 0) && (bestScaledRate < scaledRate) ) {
        bestScaledRate = scaledRate;
        puts("**");
      } else {
        puts("");
      }
      fflush( NULL );


      msDelay = msDelay + 2;

      if ( i == 0 ) break;
    }

    if (i >= 8) i++;
  }

  puts("");

  if ( EarlyExit == 1 ) {
    puts("Test stopped early by Ctrl-Break.");
  } else if ( EarlyExit == 2 ) {
    puts("Failure reading CMOS real time clock.");
  }

  setvect( 0x1b, oldCtrlBreakHandler );

  curr_unit->max_readahead = currentReadAhead*2;
  curr_unit->readahead_delay = 0;

  printf("\nRead-ahead cache restored to %d KB, use the set_max_ra command\nto set it to a new value.\n", currentReadAhead );
}



// Read-ahead works by sending a normal read request that requires a
// synchronous response, but also sending some meta-data with that
// request to tell the server how big the total read is.  That allows
// the server to send special read-ahead packets with data that will
// be requested shortly.
//
// The client processes the read-ahead data as it comes in, filling
// in the user buffer area.  While the main read loop is running it
// will check to see if a particular block is already in place
// before requesting it with a read command; if the block has already
// arrived that read command can be skipped.
//
// The total amount to read is the first read request (1KB) plus
// whatever the desired read-ahead value is.  If your read doesn't
// match that size you will see plateaus and step functions in the
// performance measurements because small fractional reads cost as
// much on a distant connection as large ones do.  For example:
//
// Reading a fixed 64KB:
//
//   Cache size 13 requires 3 read requests:
//       (1KB + 13KB read-ahead, 1KB + 13KB read-ahead, 1KB+3KB read-ahead.)
//
//   Cache size 14 requires 3 read requests:
//       (1KB + 14KB read-ahead, 1KB + 14KB read-ahead, 1KB+1KB read-ahead.)
//
//   Cache size 15 requires 2 read requests:
//       (1KB + 15KB read-ahead  1KB + 15KB read-ahead.)
//
// When talking to a remote system those 1KB read requests are high latency
// and dominate the transfer time.



AbsDiskIoRec_t descriptor;

int runTrial(int cacheKB, int testLen, int msDelay, uint32_t *scaledRate) {

  // Set the readAhead sectors on the device.
  curr_unit->max_readahead = cacheKB*2;
  curr_unit->readahead_delay = msDelay;

  uint16_t readSize = cacheKB*2 + 2;

  if ( DOS_version_major >= 4 ) {
    descriptor.startSector = 0;
    descriptor.sectorCount = readSize;
    descriptor.bufOffset = FP_OFF(testBuffer);
    descriptor.bufSegment = FP_SEG(testBuffer);
  }

  uint32_t startRetries = curr_unit->retries;

  // Start as soon as a new second flips over, and then stop as soon as we
  // have run the desired time.  We can't interrupt a read at the exact
  // time needed, so this will actually run longer than it should especially
  // on longer reads.  Longer tests minimize that error - a ten second test
  // will have a maximum of 10% error, and usually much smaller assuming
  // reads take 10s of milliseconds.

  uint16_t start = readSeconds( );
  while ( start == readSeconds( ) ) {
    if ( EarlyExit ) break;
  }
  start = readSeconds( );

  uint32_t sectorsRead = 0;
  uint16_t elapsedSeconds = 0;

  while ( 1 ) {

    if ( EarlyExit ) break;

    uint16_t stop = readSeconds( );
    elapsedSeconds = getElapsedSeconds(stop, start);

    if ( elapsedSeconds >= testLen ) break;

    int rc;
    if ( DOS_version_major < 4 ) {
      rc = absRead( TargetDriveLetter, readSize, 0, testBuffer );
    } else {
      rc = absRead_DOS4( TargetDriveLetter, &descriptor );
    }
    if ( rc == 1 ) {
      // printf("Cache: %2d KB, Delay: %d, -* READ ERROR *-", cacheKB, msDelay);
      printf("Cache: %2d KB, -* READ ERROR *-", cacheKB);
      return -1;
    }

    sectorsRead += readSize;
  }

  if ( EarlyExit ) return -2;

  // No need to check for divide by 0 here - we either ran for the minimum
  // of two seconds or we exited early.

  uint32_t rate = ((sectorsRead / 2) * 10) / elapsedSeconds;
  uint32_t rate2 = rate % 10;

  // Use this printf if you are experimenting with delays between packets.
  // printf("Cache: %2d KB, Delay: %2d, %6lu KB read in %2u seconds, %5lu.%lu KB/sec  ",
  //        cacheKB, msDelay, sectorsRead/2, elapsedSeconds, rate/10, rate2 );

  uint32_t retries = curr_unit->retries - startRetries;

  printf("Cache: %2d KB, %6lu KB read in %2u seconds, %5lu.%lu KB/sec, %lu retries  ",
         cacheKB, sectorsRead/2, elapsedSeconds, rate/10, rate2, retries );

  *scaledRate = rate;
  return 0;
}




void usage( ) {
  puts( 
    "nd_cache <command> <drive:> <options>\n"
    "\n"
    "Commands:\n"
    "  test <drive:> <n> [-ts <t> ]   Test read-ahead cache sizes for <n> seconds\n"
    "  set_max_ra <drive:> <s>        Set read-ahead for drive in KB (0 to 64KB)\n"
    "\n"
    "Options for the -ts flag are:\n"
    "  cmos   Use the CMOS clock for timing.  (Default and Recommended.)\n"
    "  jride  Use the jrIDE sidecar clock for timing.  (Also good.)\n"
    "  dos    Use DOS for timing.  (Not recommended, possibly inaccurate.)\n"
    "\n"
    "The test length can be from 3 to 20 seconds."
  );
  exit( 1 );
}



void getDriveNumber( const char *s ) {

  if (s[1] != ':' || s[2] != 0) usage( );

  if ((s[0] >= 'A' && s[0] <= 'Z')) {
    TargetDriveLetter = s[0] - 'A';
  } else if ((s[0] >= 'a' && s[0] <= 'z')) {
    TargetDriveLetter = s[0] - 'a';
  }

  if ( TargetDriveLetter == -1 ) usage( );
  return;
}



void parseArgs( int argc, char *argv[] ) {


  if ( stricmp(argv[1], "test") == 0 ) {

    if ( argc < 4 ) usage( );

    getDriveNumber( argv[2] );

    TestLen = atoi( argv[3] );
    if (TestLen < 3 || TestLen > 20) usage( );

    if ( argc == 5 ) usage( );

    if ( argc == 6 ) {
      if ( stricmp(argv[4], "-ts") == 0 ) {
        if ( stricmp(argv[5], "dos" ) == 0 ) {
          TimeSource = 2;
        } else if ( stricmp(argv[5], "cmos" ) == 0 ) {
          TimeSource = 0;
        } else if ( stricmp(argv[5], "jride" ) == 0 ) {
          TimeSource = 1;
        } else {
          printf("%s: Invalid time source specified: %s\n", argv[0], argv[5]);
          usage( );
        }
      } else {
        usage( );
      }
    }
    Operation = 1;
  }

  else if ( stricmp(argv[1], "set_max_ra") == 0 ) {
    if ( argc < 4 ) usage( );
    getDriveNumber( argv[2] );
    cacheSizeKB = atoi( argv[3] );
    if ( cacheSizeKB < 0 || cacheSizeKB > 64) usage( );
    Operation = 2;
  }

  else if ( stricmp( argv[1], "set_max_ws" ) == 0 ) {
    if ( argc < 4 ) usage( );
    getDriveNumber( argv[2] );
    maxWriteParm = atoi(argv[3]);
    if ( maxWriteParm < 1 || maxWriteParm > 32 ) usage( );
    Operation = 3;
  }

  else {
    usage( );
  }

}


