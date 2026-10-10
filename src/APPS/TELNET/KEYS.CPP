/*

   mTCP Keys.cpp
   Copyright (C) 2011-2026 Michael B. Brutman (mbbrutman@gmail.com)
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


   Description: Keyboard handling routines shared by telnet and ymodem.

   Changes:

   2012-04-29: Split out from telnet when xmodem and ymodem were added

*/


#include <stdio.h>

#include "inlines.h"
#include "keys.h"


#ifdef TELNET_UNICODE

#include "unicode.h"

// Unicode composition handling.  Compose is a special mode where you
// enter a Unicode codepoint using four hex digits.

static bool    compose_active;    // Is Compose active?
static uint8_t unicode_bytes[5];  // Includes a terminating nul char for sscanf.
static uint8_t unicode_len;       // How many hex digits have we read?

#endif



// Define a table of scan codes and actions for our commonly used special keys.
// Put the most commonly used keys first to reduce the overall amount of time
// spent searching.

typedef struct {
  uint8_t  scanCode;
  uint8_t  action;
  bool     local;
} FkeyAction_t;

FkeyAction_t fKeys[] = {
  {72, K_CursorUp,         false},
  {75, K_CursorLeft,       false},
  {77, K_CursorRight,      false},
  {80, K_CursorDown,       false},
  {73, K_PageUp,           true},
  {81, K_PageDown,         true},
  {82, K_Insert,           false},
  {83, K_Delete,           false},
  {71, K_Home,             false},
  {15, K_Backtab,          false},
  {35, K_Alt_H,            true},    // Help
  {17, K_Alt_W,            true},    // Wrapping toggle
  {18, K_Alt_E,            true},    // Local echo
  {19, K_Alt_R,            true},    // Refresh screen
  {22, K_Alt_U,            true},    // Upload
  {32, K_Alt_D,            true},    // Download
  {33, K_Alt_F,            true},    // Shell to DOS
  {45, K_Alt_X,            true},    // Exit
  {48, K_Alt_B,            true},    // Backspace type toggle
  {49, K_Alt_N,            true},    // Enter type toggle
  {130, K_Compose_Unicode, true},
};



Key_t getKey( void ) {

  Key_t rc;
  rc.action = K_NoKey;
  rc.local = 0;
  rc.normalKey = 0;

  uint16_t c = biosKeyRead( );

  // Special key?
  if ( (c & 0xff) == 0 ) {

    #ifdef TELNET_UNICODE
    if ( compose_active == true ) {
      // Hitting a special key in compose mode immediately ends compose mode.
      compose_active = false;
    }
    #endif

    uint8_t fkey = c>>8;

    for ( int i=0; i < sizeof(fKeys)/sizeof(FkeyAction_t); i++ ) {
      if ( fkey == fKeys[i].scanCode ) {
        rc.action = fKeys[i].action;
        rc.local = fKeys[i].local;
      }
    }

    #ifdef TELNET_UNICODE
    // Extra handling for Unicode Compose  Alt-Minus (-)
    if ( fkey == 130 ) {
      compose_active = true;
      unicode_len = 0;
    }
    #endif

  } else {

    #ifdef TELNET_UNICODE
    if ( compose_active == true ) {

      // If the user hits ESC end compose mode early.
      if ( (c & 0xff) == 27 ) {

        rc.action = K_NoKey;
        rc.local = 0;
        rc.normalKey = 0;
        compose_active = false;

      } else {

        unicode_bytes[unicode_len++] = ( c & 0xff );

        if ( unicode_len == 4 ) {
          compose_active = false;
          int r = sscanf( (char *)unicode_bytes, "%x", &rc.unicode_cp );
          if ( r == 1 ) {
            rc.action = K_Unicode_CP;
            rc.normalKey = Unicode::findDisplayChar( rc.unicode_cp );
          } else {
            rc.action = K_NoKey;
            rc.local = 0;
            rc.normalKey = 0;
          }

        }

      }

      return rc;
    }
    #endif

    rc.action = K_NormalKey;
    rc.normalKey = ( c & 0xff );

    if ( rc.normalKey == 13 ) {
      // Special enter key processing - we want to be able to tell the
      // difference between Enter and Ctrl-M.
      if ( (c>>8) == 0x1c ) { // This was the Enter key.
        rc.action = K_Enter;
        rc.normalKey = 0;
      }
    } else {
      // Special backspace key processing - we want to be able to tell the
      // difference between Backspace and Ctrl-H.
      if ( (c>>8) == 0x0e ) { // This was the Backspace key.
        rc.action = K_Backspace;
        rc.normalKey = 0;
      }
    }

  } // end if special key

  return rc;
}

