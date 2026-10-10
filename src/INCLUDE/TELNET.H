/*

   mTCP Telnet.H
   Copyright (C) 2009-2026 Michael B. Brutman (mbbrutman@gmail.com)
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


   Description: Basic defines for Telnet

   Changes:

   2011-05-27: Initial release as open source software

*/



#ifndef _TELNET_H
#define _TELNET_H


#define TEL_IAC  (255)

#define TELCMD_WILL (251)    // 0xFB
#define TELCMD_WONT (252)    // 0xFC
#define TELCMD_DO   (253)    // 0xFD
#define TELCMD_DONT (254)    // 0xFE

#define TELCMD_SUBOPT_BEGIN (250)
#define TELCMD_SUBOPT_END   (240)

#define TELCMD_EOF    (236)  // End of File
#define TELCMD_SUSP   (237)  // Suspend current process (job control)
#define TELCMD_ABORT  (238)  // Abort process
#define TELCMD_EOR    (239)  // End of record

#define TELCMD_NOP    (241)  // No operation
#define TELCMD_DM     (242)  // Data Mark
#define TELCMD_BRK    (243)  // Break
#define TELCMD_IP     (244)  // Interrupt process
#define TELCMD_AO     (245)  // Abort output
#define TELCMD_AYT    (246)  // Are you there?
#define TELCMD_EC     (247)  // Erase character
#define TELCMD_EL     (248)  // Erase character
#define TELCMD_GA     (249)  // Go ahead


// Telnet options our Telnet client supports

#define TELOPT_BIN       (0)  // Binary transmission
#define TELOPT_ECHO      (1)  // Echo
#define TELOPT_SGA       (3)  // Suppress go ahead
#define TELOPT_TERMTYPE (24)  // Terminal type
#define TELOPT_WINDSIZE (31)  // Window Size

// A "dummy" option that we use locally that will never be implemented
//
// We need a byte of storage in an array for each option we support.
// The "dummy" option is a catch-all that we use for options that
// we don't support.  It defaults to "We won't ask for it" and
// "We won't do it."
//
// We could save space by not allocation a byte of storage for the
// options ware are not using, but then that leads to more code so
// it doesn't work out.
#define TELOPT_DUMMY     (2)

// If you add support for an option number above TELOPT_WINDSIZE then
// you need to adjust this count to grow the options array.
#define TEL_OPTION_COUNT (32)



// Other Telnet options that might be interesting someday.

#define TELOPT_STATUS    (5)  // Status
#define TELOPT_TM        (6)  // Timing mark
#define TELOPT_SENDLOC  (23)  // Send location
#define TELOPT_TERMSPD  (32)  // Terminal speed
#define TELOPT_RFC      (33)  // Remote Flow Control
#define TELOPT_LINEMODE (34)  // Linemode
#define TELOPT_XDISPLAY (35)  // X display location
#define TELOPT_ENVVARS  (36)  // Environment variables
#define TELOPT_AUTHENT  (37)  // Authentication
#define TELOPT_ENCRYPT  (38)  // Encryption
#define TELOPT_NEWENV   (39)  // New Environment



// Maximum length of a terminal type name is 40 characters.  Space is defined
// for a trailing NULL character, but that is not transmitted.
#define TEL_TERMTYPE_LEN (41) // Includes the NULL


// One new line and two new lines

#define _NL_ "\r\n"
#define _2NL_ "\r\n\r\n"




class TelnetOpts {

  public:

    TelnetOpts( ) { reset( ); }
    void reset( void ) { memset( this, 0, sizeof( TelnetOpts ) ); }

    // The state of each option, both local and remote is incoded in the first two bits.

    inline bool isRmtOn( uint8_t opt ) { return ((optArr[opt] & 0x01) == 0x01); }
    inline bool isRmtOff( uint8_t opt ) { return ((optArr[opt] & 0x01) == 0x00); }
    inline bool isLclOn( uint8_t opt )   { return ((optArr[opt] & 0x02) == 0x02); }
    inline bool isLclOff( uint8_t opt ) { return ((optArr[opt] & 0x02) == 0x00); }

    inline void setRmtOn( uint8_t opt ) { optArr[opt] |= 0x01; }
    inline void setRmtOff( uint8_t opt ) { optArr[opt] &= 0xFE; }
    inline void setLclOn( uint8_t opt ) { optArr[opt] |= 0x02; }
    inline void setLclOff( uint8_t opt ) { optArr[opt] &= 0xFD; }


    // For each option (both local and remote), will we allow it if asked or offered?

    inline bool isWantRmtOn( uint8_t opt )  { return ((optArr[opt] & 0x04) == 0x04); }
    inline bool isWantRmtOff( uint8_t opt ) { return ((optArr[opt] & 0x04) == 0x00); }
    inline bool isWantLclOn( uint8_t opt )  { return ((optArr[opt] & 0x08) == 0x08); }
    inline bool isWantLclOff( uint8_t opt ) { return ((optArr[opt] & 0x08) == 0x00); }

    inline void setWantRmtOn( uint8_t opt )  { optArr[opt] |= 0x04; }
    inline void setWantRmtOff( uint8_t opt ) { optArr[opt] &= 0xFB; }
    inline void setWantLclOn( uint8_t opt )  { optArr[opt] |= 0x08; }
    inline void setWantLclOff( uint8_t opt ) { optArr[opt] &= 0xF7; }


    // Flip a bit if we asked for something so that we don't get into a response loop.

    inline bool isWillOrWontPending( uint8_t opt ) { return ((optArr[opt] & 0x10) == 0x10); }
    inline bool isDoOrDontPending( uint8_t opt )   { return ((optArr[opt] & 0x20) == 0x20); }

    inline void setWillOrWontPending( uint8_t opt ) { optArr[opt] |= 0x10; };
    inline void clrWillOrWontPending( uint8_t opt ) { optArr[opt] &= 0xEF; };
    inline void setDoOrDontPending( uint8_t opt )   { optArr[opt] |= 0x20; };
    inline void clrDoOrDontPending( uint8_t opt )   { optArr[opt] &= 0xDF; };


//  private:

    uint8_t optArr[ TEL_OPTION_COUNT ];

};


#endif
