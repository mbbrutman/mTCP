/*

   mTCP NetDrive (ASMINC.H)
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


   Description: Inline assembler routines for NetDrive.

*/



#ifndef _ASMINC_H
#define _ASMINC_H

#include "types.h"



// IOCTL pragmas
//
// Usage:
//
//  int rc = ioctl_read( netHandle, sizeof(net_data), &net_data );
//  int rc = ioctl_write( netHandle, sizeof(Net_data_t), &net_data );
//
// Returns 0 if an error or the number of bytes read if successful.
//
// Memory model note: The IOCTL call wants the buffer to be in ds:dx.  We're
// using the small memory model so the compiler doesn't recognize ds.  Help
// it out by setting up ds to be the same as the stack segment.

#if defined(__SMALL__) || defined(__MEDIUM__)

extern uint16_t ioctl_read( uint8_t handle, uint16_t len, void far * buf);
#pragma aux ioctl_read = \
  "mov ax, ss"           \
  "mov ds, ax"           \
  "mov ax, 4404h"        \
  "int 21h"              \
  "jnc ioctl_read1"      \
  "mov ax, 0"            \
  "ioctl_read1:"         \
  parm [bl] [cx] [dx]    \
  modify [ax]            \
  value  [ax];

extern uint16_t ioctl_write( uint8_t handle, uint16_t len, void far * buf );
#pragma aux ioctl_write = \
  "mov ax, ss"           \
  "mov ds, ax"           \
  "mov ax, 4405h"        \
  "int 21h"              \
  "jnc ioctl_write1"     \
  "mov ax, 0"            \
  "ioctl_write1:"        \
  parm [bl] [cx] [dx] \
  modify [ax]            \
  value  [ax];

#else

extern uint16_t ioctl_read( uint8_t handle, uint16_t len, void far * buf);
#pragma aux ioctl_read = \
  "mov ax, 4404h"        \
  "int 21h"              \
  "jnc ioctl_read1"      \
  "mov ax, 0"            \
  "ioctl_read1:"         \
  parm [bl] [cx] [ds dx] \
  modify [ax]            \
  value  [ax];

extern uint16_t ioctl_write( uint8_t handle, uint16_t len, void far * buf );
#pragma aux ioctl_write = \
  "mov ax, 4405h"        \
  "int 21h"              \
  "jnc ioctl_write1"     \
  "mov ax, 0"            \
  "ioctl_write1:"        \
  parm [bl] [cx] [ds dx] \
  modify [ax]            \
  value  [ax];

#endif






// Absolute Disk Read pragmas
//
// We use absolute disk reads to bypass DOS and avoid any caching or fetches
// from the FAT that it might do.  (Reading a large file is a good test, but
// it adds additional overal for FAT reads that distort things.)
//
// DOS 4 made a major change so we have to know which version of DOS is in use.

typedef struct {
  union {
    uint32_t startSector;
    struct {
      uint16_t lo;
      uint16_t hi;
    } parts;
  };
  uint16_t sectorCount;
  uint16_t bufOffset;
  uint16_t bufSegment;
} AbsDiskIoRec_t;



// DOS may trash everything except the segment registers, and DOS 2.1 certainly
// does.  So save the other registers and restore them.

#if defined(__SMALL__) || defined(__MEDIUM__)

extern int absRead( uint8_t drive, uint16_t sectors, uint16_t startSector, void far * buf );
#pragma aux absRead = \
  "push bx"           \
  "push cx"           \
  "push dx"           \
  "push bp"           \
  "push si"           \
  "push di"           \
  "push ax"           \
  "mov ax, es"        \
  "mov ds, ax"        \
  "pop ax"            \
  "int 25h"           \
  "pop ax"            \
  "jc absRead1"       \
  "mov ax, 0"         \
  "jmp absRead2"      \
  "absRead1:"         \
  "mov ax, 1"         \
  "absRead2:"         \
  "pop di"            \
  "pop si"            \
  "pop bp"            \
  "pop dx"            \
  "pop cx"            \
  "pop bx"            \
  parm [al] [cx] [dx] [es bx] \
  value [ax];

extern int absRead_DOS4( uint8_t drive, void far * desc);
#pragma aux absRead_DOS4 = \
  "push bx"           \
  "push cx"           \
  "push dx"           \
  "push bp"           \
  "push si"           \
  "push di"           \
  "push ax"           \
  "mov ax, ss"        \
  "mov ds, ax"        \
  "pop ax"            \
  "mov cx, 0xffff"    \
  "int 25h"           \
  "pop ax"            \
  "jc absRead1"       \
  "mov ax, 0"         \
  "jmp absRead2"      \
  "absRead1:"         \
  "mov ax, 1"         \
  "absRead2:"         \
  "pop di"            \
  "pop si"            \
  "pop bp"            \
  "pop dx"            \
  "pop cx"            \
  "pop bx"            \
  parm [al] [bx]      \
  value [ax];

#else

extern int absRead( uint8_t drive, uint16_t sectors, uint16_t startSector, void far * buf );
#pragma aux absRead = \
  "push bx"           \
  "push cx"           \
  "push dx"           \
  "push bp"           \
  "push si"           \
  "push di"           \
  "int 25h"           \
  "pop ax"            \
  "jc absRead1"       \
  "mov ax, 0"         \
  "jmp absRead2"      \
  "absRead1:"         \
  "mov ax, 1"         \
  "absRead2:"         \
  "pop di"            \
  "pop si"            \
  "pop bp"            \
  "pop dx"            \
  "pop cx"            \
  "pop bx"            \
  parm [al] [cx] [dx] [ds bx] \
  value [ax];

extern int absRead_DOS4( uint8_t drive, void far * desc);
#pragma aux absRead_DOS4 = \
  "push bx"           \
  "push cx"           \
  "push dx"           \
  "push bp"           \
  "push si"           \
  "push di"           \
  "mov cx, 0xffff"    \
  "int 25h"           \
  "pop ax"            \
  "jc absRead1"       \
  "mov ax, 0"         \
  "jmp absRead2"      \
  "absRead1:"         \
  "mov ax, 1"         \
  "absRead2:"         \
  "pop di"            \
  "pop si"            \
  "pop bp"            \
  "pop dx"            \
  "pop cx"            \
  "pop bx"            \
  parm [al] [ds bx]   \
  value [ax];

#endif




// Reading the time from the CMOS chip
//
// This is slow and we only get one second granularity, but it beats trying
// to compensate for dropped interrupts.
//
// The CMOS uses BCD for numbers, hence the shifting to make the values
// look like integers we can use.
//
// Presence algorithm adapted from
// https://github.com/AR1972/astro/blob/master/bios/msinit.asm#L3608

extern int isCMOSClockPresent( void );
#pragma aux isCMOSClockPresent = \
  "push bx"                 \
  "push cx"                 \
  "push dx"                 \
  "xor bx, bx"              \
  "clock_present_loop:"     \
  "xor  cx, cx"             \
  "xor  dx, dx"             \
  "mov  ah,2"               \
  "int  0x1a"               \
  "cmp  cx, 0"              \
  "jnz clock_present"       \
  "cmp  dx, 0"              \
  "jnz clock_present"       \
  "cmp bx, 1"               \
  "jz  no_clock"            \
  "inc bx"                  \
  "mov cx, 0x8000"          \
  "clock_delay_loop:"       \
  "loop clock_delay_loop"   \
  "jmp  clock_present_loop" \
  "no_clock:"               \
  "xor ax, ax"              \
  "jmp clock_exit"          \
  "clock_present:"          \
  "mov ax, 1"               \
  "clock_exit:"             \
  "pop dx"                  \
  "pop cx"                  \
  "pop bx"                  \
  value [ax];



typedef struct {
  uint8_t hours;
  uint8_t minutes;
  uint8_t seconds;
} CMOSTime_t;


#if defined(__SMALL__) || defined(__MEDIUM__)

// Read time from the CMOS clock
extern int readCMOSTime( CMOSTime_t *t  );
#pragma aux readCMOSTime = \
  "mov ah, 0x2"            \
  "int 0x1a"               \
  "jnc readCMOSTimeGood"   \
  "mov ax, 1"              \
  "jmp readCMOSTimeEnd"    \
  "readCMOSTimeGood:"      \
  "mov bl, ch"             \
  "shr bl, 1"              \
  "shr bl, 1"              \
  "shr bl, 1"              \
  "shr bl, 1"              \
  "mov ax, 10"             \
  "mul bl"                 \
  "and ch, 0xf"            \
  "add al, ch"             \
  "mov [di], al"           \
  "mov bl, cl"             \
  "shr bl, 1"              \
  "shr bl, 1"              \
  "shr bl, 1"              \
  "shr bl, 1"              \
  "mov ax, 10"             \
  "mul bl"                 \
  "and cl, 0xf"            \
  "add al, cl"             \
  "mov [di+1], al"         \
  "mov bl, dh"             \
  "shr bl, 1"              \
  "shr bl, 1"              \
  "shr bl, 1"              \
  "shr bl, 1"              \
  "mov ax, 10"             \
  "mul bl"                 \
  "and dh, 0xf"            \
  "add al, dh"             \
  "mov [di+2], al"         \
  "mov ax, 0"              \
  "readCMOSTimeEnd:"       \
  parm [di]                \
  modify [ax bx cx dx]     \
  value [ax];

#else

extern int readCMOSTime( CMOSTime_t *t  );
#pragma aux readCMOSTime = \
  "mov ah, 0x2"            \
  "int 0x1a"               \
  "jnc readCMOSTimeGood"   \
  "mov ax, 1"              \
  "jmp readCMOSTimeEnd"    \
  "readCMOSTimeGood:"      \
  "mov bl, ch"             \
  "shr bl, 1"              \
  "shr bl, 1"              \
  "shr bl, 1"              \
  "shr bl, 1"              \
  "mov ax, 10"             \
  "mul bl"                 \
  "and ch, 0xf"            \
  "add al, ch"             \
  "mov [di], al"           \
  "mov bl, cl"             \
  "shr bl, 1"              \
  "shr bl, 1"              \
  "shr bl, 1"              \
  "shr bl, 1"              \
  "mov ax, 10"             \
  "mul bl"                 \
  "and cl, 0xf"            \
  "add al, cl"             \
  "mov [di+1], al"         \
  "mov bl, dh"             \
  "shr bl, 1"              \
  "shr bl, 1"              \
  "shr bl, 1"              \
  "shr bl, 1"              \
  "mov ax, 10"             \
  "mul bl"                 \
  "and dh, 0xf"            \
  "add al, dh"             \
  "mov [di+2], al"         \
  "mov ax, 0"              \
  "readCMOSTimeEnd:"       \
  parm [ds di]             \
  modify [ax bx cx dx]     \
  value [ax];

#endif




#endif
