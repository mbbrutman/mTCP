; mTCP NetDrive (SIMPLE.ASM)
; Copyright (C) 2023-2026 Michael B. Brutman (mbbrutman@gmail.com)
; mTCP web page: http://www.brutman.com/mTCP/mTCP.html
;
;
; This file is part of mTCP.
;
; mTCP is free software: you can redistribute it and/or modify
; it under the terms of the GNU General Public License as published by
; the Free Software Foundation, either version 3 of the License, or
; (at your option) any later version.
;
; mTCP is distributed in the hope that it will be useful,
; but WITHOUT ANY WARRANTY; without even the implied warranty of
; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
; GNU General Public License for more details.
;
; You should have received a copy of the GNU General Public License
; along with mTCP.  If not, see <http://www.gnu.org/licenses/>.
;
; Description: The device driver code.
;
; Why is this called SIMPLE.ASM?  Because I started with a very simple
; character mode device driver.  The name is a tribute to that very
; simple original piece of code.




; UDP Testing
;
; If you add -dCHKSUM_TESTING to the wasm command line in the makefile you will
; enable some extra code that can be used for testing the IP and UDP checksum
; routines.  The extra code can be called as a far function and is used with
; a test program that generates random data, calls the IP and UDP checksum
; functions, and then compares the result with known good implementations.


Max_Units equ 24


cseg    segment para public 'code'
net     proc far
        assume cs:cseg, es:cseg, ds:cseg


include "RH.ASM"
include "PKT.ASM"
include "BPB.ASM"
include "SHARED.ASM"
include "SHIM.ASM"


; ============================================================================
;
; Device Driver Header

begin:

next_dev           dd          -1
attribute          dw          0x6002          ; Block device, IOCTL, non-IBM format, 32 bit LBAs
strategy           dw          dev_strategy    ; Strategy routine offset
interrupt          dw          dev_int         ; Interrupt routine offset
unit_count         db          4               ; Supports up to 4 units.
                   db          'NETDRV '       ; 7 more chars, unused by block drivers


; ============================================================================
;
; Local data - please keep everything on even boundaries.

                   even
rh_off             dw          ?               ; request header offset
rh_seg             dw          ?               ; request header segment


; This both an eye-catcher and our version number.  It must immediately
; preceed the shared data area or the EXE won't be able to find it.

                   db          'NETDRIVE', 0x00, SHARED_DATA_VERSION
shared_data        net_data    <>

                   even
                   db          'DEBUG   '
pkt_dbg1           dw          0
pkt_dbg2           dw          0



; Currently executing (or last command)
;
; DOS reads and writes are executed by breaking them up into smaller network
; reads and writes.  These variables keep the state of the current command
; execution.

                   db          'COMMAND '
cmd_op             db          ?               ; operation (our protocol)
cmd_result         db          ?               ; Result code from server
cmd_start          dd          ?               ; Starting sector
cmd_count          dw          ?               ; Remaing sector count
cmd_user_buf_off   dw          ?               ; User buffer offset
cmd_user_buf_seg   dw          ?               ; User buffer segment
cmd_sectors_req    dw          ?               ; Sectors requested in the last UDP pkt?
cmd_retry_count    dw          ?               ; Countdown retry for current packet
cmd_resp_recved    db          0               ; Do we have a response yet?
cmd_active         db          0               ; Are we even waiting for a response?
cmd_output_crc_lcl dd          ?               ; CRC or checksum if we are doing write verify
cmd_output_crc_rmt dd          ?               ; Received CRC or checksum from the server

curr_unit          dw          ?               ; Offset to the current unit_data


; Local variables used only during the output command.

local_user_seg     dw         ?                ; Local copy of cmd_user_buf_seg.
fragment_offset    dw         ?                ; Fragment offset of the next packet. (Multiples of 8 bytes)
output_udp_len     dw         ?                ; Length of the entire UDP payload; sent in the UDP header.
partial_chksum     dw         ?                ; NetDrive command and NetDrive payload checksum

paras_to_send      dw         ?                ; Paragraphs (16 byte chunks) left to send.
paras_this_pkt     dw         ?                ; Paragraphs going into the next outgoing packet.


; Misc networking stuff: IP and ARP housekeeping

ip_ident           dw          ?               ; IP ident; increases each time we send a packet
sendAttempts       db          ?               ; How many attempts to make when pushing a packet out
                   db          ?               ; Padding

                   db          'ARP DATA'
arp_pending        db          0               ; Is there a pending ARP request to respond to?
                   db          0               ; Padding

eth_broadcast      db          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff


; Timer
;
; Keep an address to the original interrupt vector before we hooked it
; so that we can chain to it.  Also define a countdown timer that we use
; for timeout detection.

                   even
                   db          'TIMER   '
timerOrigInt       dd          ?               ; Original interrupt vector before we hooked it
countdownTimer     dw          0               ; Use for detecting timeouts

delayParm          dw          0               ; Parameter for the delay routine.

; Packet driver shim stuff

                   even
                   db           "HANDLES "
handles_in_use     dw 0                        ; How many handles are active.
handle_found       dw ?                        ; Temp var used during handle searches.
handles handle_rec MAX_HANDLES dup(<>)         ; The handle table.
end_handles        label byte                  ; An easy way to detect when we past the table.



; Private stacks
;
; Sizes are chosen based on experience with a few machines and need to be
; generous because we don't know what code we are interrupting, what code
; is calling DOS that is calling us, or what packet driver might be in use.

                   even
                   db          'STACKTIM'
stack_ptr_timerint dw          ?
stack_seg_timerint dw          ?
                   db          255 dup ('X')
                   db          0
stack_top_timerint equ         $-2

                   even
                   db          'STACKRCV'
stack_ptr_recvint  dw          ?
stack_seg_recvint  dw          ?
                   db          127 dup ('Y')
                   db          0
stack_top_recvint  equ         $-2

                   even
                   db          'STACKINT'
stack_ptr_dosint   dw          ?
stack_seg_dosint   dw          ?
                   db          255 dup ('Z')
                   db          0
stack_top_dosint   equ         $-2


switchToStack macro stackname:REQ
  ; Order is important - always update SS first, then SP to take advantage of
  ; the x86 deferring interrupts until after SP is updated.
  push ax
  mov cs:stack_seg_&stackname, ss
  mov cs:stack_ptr_&stackname, sp
  mov ax, cs
  mov ss, ax
  mov sp, OFFSET stack_top_&stackname
endm


switchFromStack macro stackname:REQ
  ; Order is important - always update SS first, then SP to take advantage of
  ; the x86 deferring interrupts until after SP is updated.
  mov ss, cs:stack_seg_&stackname
  mov sp, cs:stack_ptr_&stackname
  pop ax
endm


; Packet buffers
;
; An incoming and outgoing packet buffer used to be statically allocated.
; That was ok when the buffers were not large, but then the incoming
; buffer had to grow to the full size to allow for the packet driver shim
; code, and now the outgoing buffer also has to be full sized for streaming
; writes.  So instead of burning the disk space for them by statically
; allocating them, we now dynamically allocate them.

                   even
incoming_pkt_len   dw         ?
incoming_buf_p     dw         ?
outgoing_buf_p     dw         ?



; Tiny Ramdisk to use while a virtual drive is not connected.
include "RAMDISK.ASM"

include "READAH.ASM"

include "CRC.ASM"
include "FLETCHER.ASM"



; ============================================================================
;
; Start of code!


; strategy routine - just saves the pointers to the request header.

dev_strategy:
  mov cs:rh_seg, es
  mov cs:rh_off, bx
  ret



; interrupt - does the actual work on the saved request header.

dev_int:

  ; Switch to a private stack first.  We use stack3 here.
  ; Order is important - always update SS first, then SP to take advantage of
  ; the x86 deferring interrupts until after SP is updated.

  switchToStack dosint

  pushf
  push   bx
  push   cx
  push   dx
  push   bp
  push   si
  push   di
  push   ds
  push   es

  ; Clear the direction flag; we never want to go backwards.  The pushf
  ; above preserves the original state for when we return, as per the
  ; DOS device driver programming guidelines.
  cld

  ; Restore pointer to request header in ES:BX for commands
  mov    ax, cs:rh_seg
  mov    es, ax
  mov    bx, cs:rh_off

  ; Make our data addressable in DS
  mov    ax, cs
  mov    ds, ax

  ; Set a default good return code
  mov    es:[bx].rh_status, 0000h

  ; Get addressability to the unit data
  xor    dx, dx
  mov    dl, es:[bx].rh_unit
  mov    ax, size unit_data
  mul    dx
  add    ax, OFFSET units_storage
  mov    curr_unit, ax

  ; Jump to the appropriate command.
  mov    al, es:[bx].rh_cmd
  cmp    al, 12
  jle    dev_int_good_cmd

  ; Whoops - we don't handle this one.
  mov    es:[bx].rh_status, 0x8003
  jmp    done

  dev_int_good_cmd:
  rol    al, 1                      ; Multiply by two so we can use cmdtab.
  mov    ah, 0
  mov    di, OFFSET cmdtab
  add    di, ax
  jmp    word ptr[di]

cmdtab   label  byte
         dw     cmd_init            ;  0: Initialization
         dw     cmd_media_check     ;  1: Media check
         dw     cmd_get_bpb         ;  2: Build BPB
         dw     cmd_ioctl_input     ;  3: IOCTL input
         dw     cmd_input           ;  4: Input (read)
         dw     done                ;  5: Char only: Non-destrutive input
         dw     done                ;  6: Char only: Input status
         dw     done                ;  7: Char only: Input flush
         dw     cmd_output          ;  8: Output (write)
         dw     cmd_output_verify   ;  9: Output with verify
         dw     done                ; 10; Char only: Output status
         dw     done                ; 11: Char only: Output flush
         dw     done                ; 12: IOCTL output (not used)


cmd_init:

  ; Almost all of the work, including setting the proper fields in the
  ; request header is done in the initial call.  We want as much done
  ; there to avoid having any code here, which is just dead bytes after
  ; initialization is complete.

  call   initial

  ; Clear the unit storage area; all of the registers are already setup
  ; to do this.  On the error path CX will be zero and this will be a no-op.
  rep    stosw

  ; Restore ES:BX to set 'done' in the RH before ending.
  mov    ax, cs:rh_seg
  mov    es, ax
  mov    bx, cs:rh_off

  jmp    done



; Media Check
;
; We did not set the "Removable Media" attribute so there is no need to set
; the previous volume label pointer.  If we wanted to set it to be safe we'd
; need to check the DOS version too to avoid stomping on storage that DOS 2.x
; doesn't allocate in the RH.
;
; This is really simple; we rely on NETDRIVE.EXE to set unit_media_check to
; changed whenever it does something to the drive.  When DOS calls here and
; is told that the media changed, it will call Get BPB, which will then
; set unit_media_check back to no-change.
;
; The only edge case here is when we are first starting up and the RAM disk
; is being used.  The initial state of unit_media_check is 0 (unknown), which
; works out fine - there are no dirty buffers possible so DOS will assume the
; media ; has changed.  It will call Get BPB which will set it to unchanged,
; and all is good.
;
cmd_media_check:

  mov    si, curr_unit
  mov    al, [si].unit_media_check
  mov    es:[bx].rh_media_return, al
  jmp    done


; Get BIOS Parameter Block (BPB)
;
cmd_get_bpb:

  ; Reset the unit_media_check value to unchanged.
  mov    si, curr_unit
  mov    [si].unit_media_check, 1

  ; One way or the other, we are pointing at something in our code segment.
  mov    word ptr es:[bx].rh_get_bpb_bpb_seg, cs

  ; If the session number is 0 we are not connected and will return a BPB
  ; for the tiny RAM disk.  If we are connected we use the real BPB for the drive.
  cmp    [si].unit_session, 0
  jnz    cmd_get_bpb_connected

  mov    word ptr es:[bx].rh_get_bpb_bpb_off, OFFSET RamDiskBPB
  jmp    done
  
  cmd_get_bpb_connected:
  add    si, unit_bpb
  mov    word ptr es:[bx].rh_get_bpb_bpb_off, si
  jmp    done



; IOCTL input - read from the driver.

cmd_ioctl_input:

  ; If there are less than 8 bytes to write to fail the operation.
  cmp    es:[bx].rh_ioctl_count, 8
  jae    cmd_ioctl_input1

  ; Set a bad return code and leave.
  mov    es:[bx].rh_ioctl_count, 0
  mov    es:[bx].rh_status, 0x800c
  jmp    done


  cmd_ioctl_input1:

  ; Copy two far pointers to the user buffer:
  ;  * net_data structure
  ;  * address to the current unit structure

  ; ES needs to temporarily point at their buffer, so save it first.
  push   es

  ; Create a far pointer to the user buffer in ES:DI.
  les    di, es:[bx].rh_ioctl_buf_off

  mov    ax, OFFSET shared_data   ; net_data offset
  stosw
  mov    ax, cs                   ; net_data segment
  stosw

  mov    ax, curr_unit            ; curr_unit offset
  stosw
  mov    ax, cs                   ; curr_unit segment
  stosw

  ; Restore the rh segment
  pop    es

  ; Write the return code (number of bytes written)
  mov    es:[bx].rh_ioctl_count, 8

  jmp    done




; Input (Read) from the driver
;
; Perform a read.  The read will be done two sectors at a time if possible
; for performance reasons.  Any bad return code from the server halts the
; entire operation.
;
cmd_input:

  mov    cmd_active, 1

  ; If the packet drive is not connected use the fake ram drive area
  mov    si, curr_unit
  cmp    [si].unit_session, 0
  jne    cmd_input_connected


  ; Reading from the RamDisk structure
  ;
  ; DOS is generally OK with the RamDisk having 64 byte sectors (which is
  ; legal) but a lot of tools and other code assume 512 byte sectors.
  ; We are going to be clever here and artifically inflate the RamDisk
  ; sectors from 64 bytes to 512 bytes; everything we need is in the first
  ; 64 bytes of a sector so we can generate zeros for the rest.

  ; Get the starting LBA
  mov    ax, es:[bx].rh_input_start

  ; If this is later DOS being silly and using a 32 bit LBA for our four
  ; sector RAM disk use the alternate location for the start LBA.
  cmp    ax, 0xffff
  jne    cmd_input_1
  mov    ax, word ptr es:[bx].rh_input_hugeStart

  cmd_input_1:

  ; AX has the starting sector now.

  ; Get the sector count
  mov    dx, es:[bx].rh_input_count

  ; Set ES:DI up to point to their target buffer
  mov    di, es:[bx].rh_input_buf_off
  mov    es, es:[bx].rh_input_buf_seg

  cmd_input_ramdisk_loop_top:

    push   ax

    ; Compute an offset into the RamDisk structure
    mov    cl, 6
    shl    ax, cl
    add    ax, OFFSET RamDisk

    ; Copy 64 bytes using words.
    ; Using MOVSW so source is in DS:SI, target is in ES:DI
    mov    si, ax
    mov    cx, 32
    rep    movsw

    ; Generate 448 bytes of zeros
    mov    cx, 224
    xor    ax, ax
    rep    stosw

    ; Get the sector number back
    pop    ax

    inc    ax
    dec    dx
    jnz    cmd_input_ramdisk_loop_top

  jmp    cmd_input_finished_good


  cmd_input_connected:
  mov    cmd_op, Op_Read

  call   setup_cmd_vars

  ; Everything we need is in the cmd_ variables and we are done with the
  ; RH for now.  Set ES so we can use it for our data.
  mov    ax, cs
  mov    es, ax


  ; Setup outgoing UDP command header
  ; These fields do not change even when reading multiple sectors.

  mov    bx, outgoing_buf_p
  mov    [bx].out_udp_start.pkt_nd_vers, ND_PROTOCOL_VERSION
  mov    si, curr_unit
  mov    ax, [si].unit_session
  mov    [bx].out_udp_start.pkt_nd_session, ax
  mov    [bx].out_udp_start.pkt_nd_op, Op_Read

  ; Clear out other fields in the header that won't be used.  Result doesn't
  ; need to be cleared because the server is the only thing to set it, but
  ; I'd rather see a 0 there in the packet traces.
  mov    [bx].out_udp_start.pkt_nd_result, 0
  mov    [bx].out_udp_start.pkt_nd_cmdext, 0
  

  ; This is a new read from our caller in DOS.  This invalidates
  ; previously received read-ahead data because the user buffer or
  ; drive they are reading may have changed.  (We could check for
  ; both and if it is an exact re-read of the same LBAs from the save
  ; drive keep our read-ahead data, but that is not likely.)
  ;
  ; This has to be done with interrupts disabled because we never know
  ; when a packet might come in and start to be processed.

  pushf
  cli

  ; Invalidate the read-ahead bitmap
  mov    di, OFFSET ra_slot_valid
  xor    ax, ax
  stosw
  stosw
  stosw
  stosw
  stosw
  stosw
  stosw
  stosw
  stosw


  ; Record the current sequence number.  This will be used to filter
  ; out delayed or old read-ahead data.  SI still has curr_unit.
  mov    ax, [si].unit_sequence
  mov    ra_seq_start, ax

  ; Save the most current LBA start and block count issued by DOS.
  mov    ax, word ptr cmd_start
  mov    word ptr ra_lba_start, ax
  mov    ax, word ptr cmd_start+2 ; High 16 bits
  mov    word ptr ra_lba_start+2, ax

  mov    ax, cmd_count
  mov    ra_lba_count, ax

  ; Save the user buffer starting address.
  mov    ax, cmd_user_buf_off    ; User buffer offset
  mov    ra_buf_off, ax
  mov    ax, cmd_user_buf_seg    ; User buffer segment
  mov    ra_buf_seg, ax

  popf


  ; Setup the loop to do multiple sectors.  Try to do two at a time
  ; until there are one or zero left.

  cmd_input_loop_top:
  cmp    cmd_count, 0
  jz     cmd_input_finished_good



  ; Check to see if this block already arrived.  If it did the bit that
  ; represents the block will be on.

  ; Disable interrupts to prevent new blocks being received from changing things
  ; while we are looking at them.
  pushf
  cli


  ; What bit in the readahead bitmap are we looking at?

  ; These are 32 bit quantities but we never have a difference that can overflow
  ; a 16 bit counter so ignore the upper word of the counters.
  mov    ax, word ptr cmd_start
  sub    ax, word ptr ra_lba_start

  ; If AX comes up as zero this is the first sector which we issued a read for.
  ; That's never going to be filled in on a read-ahead, so exclude it.

  cmp    ax, 0
  jz     cmd_input_not_in_cache

  cmp    ax,RA_MAX_BLOCK
  ja     cmd_input_not_in_cache

  ; Figure out which byte of ra_slot_valid to get and load it into BL
  mov    bx, ax
  shr    bx, 1
  shr    bx, 1
  shr    bx, 1
  add    bx, OFFSET ra_slot_valid
  mov    bl, byte ptr [bx]
  xor    bh, bh

  ; Isolate the bit in AX
  and    ax, 0x7
  mov    cx, ax
  mov    ax, 1
  shl    ax, cl

  test   bx, ax
  jz     cmd_input_not_in_cache


  ; Bump the start LBA, decrement the count and advance the target
  ; buffer address.

  add    word ptr cmd_start, 1           ; 32 bits so add with carry.
  adc    word ptr cmd_start+2, 0         ; Capture the carry bit.
  add    cmd_user_buf_seg, 0x20          ; Advance 512 bytes
  dec    cmd_count                       ; Update the number of sectors left to do.

  popf                                   ; Reenable interrupts
  jmp    cmd_input_loop_top              ; And go back to do it all again ...
  

  cmd_input_not_in_cache:

  popf                                   ; Reenable interrupts


  cmd_input_send_req:

  mov    ax, shared_data.net_pkt_retries ; Reset the retry counter
  mov    cmd_retry_count, ax 

  cmd_input_loop_retry_top:


  ; Set outgoing Sequence, Start and Count in the outgoing packet.
  ; Also make a note of how many blocks we are requesting in this
  ; packet.

  mov    bx, outgoing_buf_p
  mov    si, curr_unit

  mov    ax, [si].unit_sequence
  mov    [bx].out_udp_start.pkt_nd_sequence, ax

  mov    ax, word ptr cmd_start
  mov    word ptr [bx].out_udp_start.pkt_nd_start, ax
  mov    ax, word ptr cmd_start+2
  mov    word ptr [bx].out_udp_start.pkt_nd_start+2, ax

  mov    dx, 1                           ; Doing at least one
  cmp    cmd_count, 1
  jz     set_outgoing_ssc_just_one
  inc    dx                              ; Doing two.

  set_outgoing_ssc_just_one:
  mov    cmd_sectors_req, dx
  mov    [bx].out_udp_start.pkt_nd_count, dx


  ; Get ready to set up the outgoing packet.
  mov    dx, UDP_ND_LEN                  ; UDP header and fixed len command header.

  
  ; Set read-ahead in the outgoing packet payload.  Only set the blocks we
  ; intend to read and not just blindly use the full readahead count.
  ; Also bump the packet length to reflect this additional data.
  ; BX is still set to outgoing_buf_p.

  xor    ax, ax
  mov    al, [si].unit_max_readahead     ; si is still pointing to curr_unit.
  mov    word ptr [bx].out_udp_start.pkt_nd_data, ax
  mov    ax, cmd_count
  mov    word ptr [bx].out_udp_start.pkt_nd_data+2, ax
  xor    ax, ax
  mov    al, [si].unit_ra_delay
  mov    word ptr [bx].out_udp_start.pkt_nd_data+4, ax
  add    dx, 6                           ; Add six for the read-ahead optional data


  ; Fill in the Eth, IP, and UDP headers and send the packet.
  ; After the packet has been sent, setup the countdown timer.

  mov    cmd_resp_recved, 0


  ; Code to replace sendUDP
  xor    bx, bx                          ; No need to call prepIpFlags
  call   setEthIpHeaders                 ; DX has the UDP payload length for the IP header.
  xor    ax, ax                          ; No partial checksum computed yet.
  call   setUdpHeader                    ; Uses AX and DX
  mov    cx, dx                          ; DX has the UDP payload length
  add    cx, 0x22                        ; Add the Eth and IP headers
  call   sendPacket


  mov    ax, shared_data.net_pkt_timeout
  mov    countdownTimer, ax

  cmd_input_spinwait:
  ; Now spin and wait for the response
  cmp    cmd_resp_recved, 1
  jz     cmd_input_check_result

  cmp    countdownTimer, 0
  jnz    cmd_input_spinwait

  ; Timeout ..
  cmp    cmd_retry_count, 0
  jz     cmd_input_timeout

  ; Nothing should have moved so just go back to the top of the loop and try again.

  mov    si, curr_unit
  add    word ptr [si].unit_blocks_retries, 1
  adc    word ptr [si].unit_blocks_retries+2, 0

  dec    cmd_retry_count
  jmp    cmd_input_loop_retry_top


  cmd_input_check_result:

  cmp    cmd_result, 0
  jnz    cmd_input_bad_result


  ; The last response was good.  Advance the loop variables and update the stats.

  mov    si, curr_unit
  mov    ax, cmd_sectors_req
  add    word ptr [si].unit_blocks_read, ax
  adc    word ptr [si].unit_blocks_read+2, 0

  call   update_local_ssc                ; Update our local Sequence, Start and Count
  jmp    cmd_input_loop_top              ; And go back to do it all again ...


  cmd_input_finished_good:
  ; Restore rh header and segment
  ; The number of sectors read should already be in the RH.
  mov    ax, cs:rh_seg
  mov    es, ax
  mov    bx, cs:rh_off
  jmp    done


  ; Bad result means we got a response, so update the sequence number.
  ; Then continue through the timeout code because both report an error.
  cmd_input_bad_result:
  mov    si, curr_unit
  inc    [si].unit_sequence

  cmd_input_timeout:
  ; Restore rh header and segment
  mov    ax, cs:rh_seg
  mov    es, ax
  mov    bx, cs:rh_off

  ; Give them a general read fault and the number of sectors read.
  ; Tell them it was a read fault.  Given this is a timeout it could
  ; be a "drive not ready" too but read fault works for both timeout
  ; and bad result.

  mov    es:[bx].rh_status, 0x800b
  mov    ax, es:[bx].rh_input_count      ; Total number of sectors -
  sub    ax, cmd_count                   ; Sectors still left to transfer
  mov    es:[bx].rh_input_count, ax      ; Successful sectors transfered.
  jmp    done



cmd_output_verify:
  mov cmd_op, Op_Write_Verify
  jmp cmd_output_common

cmd_output:
  mov cmd_op, Op_Write
  ; Fall through because normal writes are our fast path.



; Output (Write) from the driver
;
; Perform a write.  This is basically the same as the read, except here we
; copy the user data first into the outgoing buffer.  As with read we try
; to do two sectors at a time.
;
cmd_output_common:

  mov    cmd_active, 1

  ; Are we connected?  If not, just return an error - we don't support writing
  ; to the ram disk.
  mov    si, curr_unit
  cmp    [si].unit_session, 0
  jnz    cmd_output_connected

  jmp cmd_output_write_protect

  cmd_output_connected:
  ; Even if we are connected we might be read-only.
  cmp    [si].unit_readonly, 0
  jz     cmd_output_rw

  cmd_output_write_protect:
  mov    es:[bx].rh_status, 0x8000
  mov    es:[bx].rh_input_count, 0
  jmp    done

  cmd_output_rw:

  call   setup_cmd_vars

  ; Everything we need is in the cmd_ variables and we are done with the
  ; RH for now.  Set ES so we can use it for our data.
  mov    ax, cs
  mov    es, ax


  cmd_output_loop_top:
  cmp    cmd_count, 0
  jz     cmd_output_loop_finished

  mov ax, shared_data.net_pkt_retries    ; Reset the retry counter
  mov cmd_retry_count, ax 


  cmd_output_loop_retry_top:

  ; Setup the outgoing NetDrive command header and compute how many sectors
  ; we will send in this group.

  mov    si, curr_unit

  mov    bx, outgoing_buf_p
  mov    [bx].out_udp_start.pkt_nd_vers, ND_PROTOCOL_VERSION
  mov    ax, [si].unit_session
  mov    [bx].out_udp_start.pkt_nd_session, ax
  mov    ax, [si].unit_sequence
  mov    [bx].out_udp_start.pkt_nd_sequence, ax
  mov    al, cmd_op
  mov    [bx].out_udp_start.pkt_nd_op, al
  mov    ax, word ptr cmd_start
  mov    word ptr [bx].out_udp_start.pkt_nd_start, ax
  mov    ax, word ptr cmd_start+2
  mov    word ptr [bx].out_udp_start.pkt_nd_start+2, ax

  ; Clear out other fields in the header that won't be used.  Result doesn't
  ; need to be cleared because the server is the only thing to set it, but
  ; I'd rather see a 0 there in the packet traces.
  mov    [bx].out_udp_start.pkt_nd_result, 0


  ; Figure out how many blocks we are going to send under this command.

  xor    dx, dx
  mov    dl, [si].unit_max_write_size
  cmp    cmd_count, dx                       ; cmd_count is the remaining block count
  jae    cmd_output_max_blocks
  mov    dx, cmd_count
  cmd_output_max_blocks:
  ; Update the sectors requested for this iteration and also set it in the packet.
  mov    cmd_sectors_req, dx
  mov    [bx].out_udp_start.pkt_nd_count, dx


  ; Set CRC algorithm in the cmdext field.  At 4KB and below we use CRC-CCITT 16
  ; and above 4K we use Fletcher-32.
  ;
  ; We are being lazy here; this only needs one byte, and probably even only
  ; one bit.  But treating it as a word will zero out the other byte for us.

  xor    ax, ax                               ; Default: not a write verify.
  cmp    cmd_op, Op_Write
  je     cmd_output_cmdext_set
  inc    ax                                   ; AX=1: CRC-CCITT 16 bit
  cmp    dx, 9
  jb     cmd_output_cmdext_set
  inc    ax                                   ; AX=2: Fletcher-32
  cmd_output_cmdext_set:
  mov    [bx].out_udp_start.pkt_nd_cmdext, ax


  ; Instead of counting sectors to send, let's count paragraphs (16 byte chunks)
  ; to send.  That gets us close to perfectly filling packets without having to
  ; mess with the offsets.
  mov    cl, 5
  shl    dx, cl
  mov    paras_to_send, dx


  ; Make a local copy of the user buffer segment.  This copy gets advanced as
  ; we send fragments, while the original only advances after we are told the
  ; write has completed.  (A copy of the offset is not needed, as the offset
  ; is never modified so we can use cmd_user_buf_off.)
  mov    ax, cmd_user_buf_seg
  mov    local_user_seg, ax

  mov    fragment_offset, 0


  ; Figure out how many paragraphs of user data are going into the next packet.
  ; Start with the MTU then subtract 20 for the IP header, 8 for the UDP header
  ; and 16 for the NetDrive command header.
  mov    dx, shared_data.net_my_mtu
  sub    dx, (IP_HDR_LEN + UDP_ND_LEN)       ; Subtract 20 for IP header, 8 for UDP
  shr    dx, 1                               ; Divide by 16
  shr    dx, 1
  shr    dx, 1
  shr    dx, 1

  ; DX has paragraphs available in the next packet.  Assume we are going to fill it.
  mov    paras_this_pkt, dx
  cmp    paras_to_send, dx
  ja     cmd_output_pkt_paras_set
  mov    dx, paras_to_send
  mov    paras_this_pkt, dx
  cmd_output_pkt_paras_set:


  ; SW: Sending packets
  ;
  ; * Compute a partial checksum over the user data in the original user
  ;   buffer, as we need this for the UDP header in the first packet.
  ; * Send the first packet with the UDP header.
  ;   * If everthing is going to fit, do not turn on the fragment flag.
  ; * If there is more data, loop and send out the remaining data.


  ; Compute a partial checksum for the command header and then the user data.

  mov    cx, ND_LEN
  lea    si, [bx].out_udp_start.pkt_nd_vers
  xor    bx, bx
  call   computeUdpDataChecksum

  ; Now we have a partial checksum for the header in AX.  Do it for the user data now.

  mov    dx, cmd_sectors_req             ; Given 512 byte blocks, compute number of bytes.
  mov    dh, dl                          ; Fast shift to mult by 256.
  xor    dl, dl                          ; Clear lower byte as part of the mult by 256.
  shl    dx, 1                           ; One more shift to get to bytes.

  mov    cx, dx
  mov    si, cmd_user_buf_off
  mov    ds, local_user_seg              ; Order is important here ... muck up DS last.
  mov    bx, ax                          ; Pass in the partial checksum we computed earlier.
  call   computeUdpDataChecksum

  ; Save AX momentarily while we restore DS
  push   ax
  mov    ax, cs
  mov    ds, ax
  pop    ax

  ; Save the partial checksum away for later
  mov    partial_chksum, ax

  ; Also save the UDP data length away for later.  Include the UDP and command header too.
  mov    output_udp_len, dx
  add    output_udp_len, UDP_ND_LEN



  ; First packet: Copy user data to the UDP payload area.
  ; Using MOVSW so source is in DS:SI, target is in ES:DI

  mov    cx, paras_this_pkt              ; Put the number of words in CX
  shl    cx, 1
  shl    cx, 1
  shl    cx, 1

  mov    dx, cx                          ; Set the number of bytes in DX
  shl    dx, 1

  mov    bx, outgoing_buf_p
  lea    di, [bx].out_udp_start.pkt_nd_data
  mov    si, cmd_user_buf_off
  mov    ds, local_user_seg              ; Order is important here ... muck up DS last.

  rep    movsw                           ; Do the copy

  mov    ax, cs                          ; Restore ds
  mov    ds, ax


  ; DX has the length of the raw data we are sending in this specific packet.
  ; This is the first packet, so add the UDP and NetDrive command header to
  ; the length.  (Subsequent fragment packets, if any, don't get the headers
  ; repeated.)
  add    dx, UDP_ND_LEN


  ; Fill in the Eth, IP, and UDP headers and send the packet.
  ; After the packet has been sent, setup the countdown timer.

  mov    cmd_resp_recved, 0

  push   dx                              ; Save this packet payload length for sendPacket
  call   prepIpFlags                     ; Figure out the IP header flags and fragment offset.
  call   setEthIpHeaders                 ; Uses BX (flags) and DX (Payload length, not counting IP or Eth)
  mov    ax, partial_chksum              ; Pass in the chksum computed over the NetDrive command header and the payload.
  mov    dx, output_udp_len              ; This is not the length for this packet; it's the total UDP payload length!
  call   setUdpHeader                    ; Uses AX and DX
  pop    cx                              ; Restore the UDP payload length of this packet, previously pushed as DX
  add    cx, 0x22                        ; Add the Ethernet and IP headers to it.
  call   sendPacket




  ; Bump the first fragment because it also had a command header and a UDP header.
  add    fragment_offset, (UDP_ND_LEN / 8)


  cmd_output_fragment_loop:

  mov    ax, shared_data.net_pkt_send_dly ; If this is zero delay will return back immediately.
  mov    delayParm, ax
  call   delay

  ; Decrement the remaining paragraphs to send, advance the local user buffer pointer,
  ; and update the fragment index.
  mov    ax, paras_this_pkt
  sub    paras_to_send, ax

  add    local_user_seg, ax

  shl    ax, 1
  add    fragment_offset, ax


  ; SW: Is there more data to send?  If so, copy the user data to the packet data area,
  ; call setEthIPHeaders, and then send it out.  Loop until there is no more data.


  cmp    paras_to_send, 0
  jz     cmd_output_wait



  ; Figure out how many paragraphs we are sending this time.
  mov    dx, shared_data.net_my_mtu
  sub    dx, IP_HDR_LEN
  shr    dx, 1                               ; Divide by 16
  shr    dx, 1
  shr    dx, 1
  shr    dx, 1

  ; DX has paragraphs available in the next packet.  Assume we are going to fill it.
  mov    paras_this_pkt, dx
  cmp    paras_to_send, dx
  ja     cmd_output_pkt_paras_set2
  mov    dx, paras_to_send
  mov    paras_this_pkt, dx
  cmd_output_pkt_paras_set2:


  ; Copy the user data into the packet.  There is no UDP header this time.
  ; Using MOVSW so source is in DS:SI, target is in ES:DI

  mov    cx, paras_this_pkt              ; Put the number of words in CX
  shl    cx, 1
  shl    cx, 1
  shl    cx, 1

  mov    dx, cx                          ; Set the number of bytes in DX
  shl    dx, 1

  mov    bx, outgoing_buf_p
  lea    di, [bx].out_udp_start
  mov    si, cmd_user_buf_off
  mov    ds, local_user_seg              ; Order is important here ... muck up DS last.

  rep    movsw                           ; Do the copy

  mov    ax, cs                          ; Restore ds
  mov    ds, ax


  ; Send the fragment out

  call   prepIpFlags                     ; Figure out the IP header flags and fragment offset.
  call   setEthIpHeaders                 ; Uses BX (flags) and DX (Payload length, not counting IP or Eth)
  mov    cx, dx                          ; Restore the UDP payload length of this packet, previously pushed as DX
  add    cx, 0x22                        ; Add the Ethernet and IP headers to it.
  call   sendPacket

  jmp    cmd_output_fragment_loop



  cmd_output_wait:

  ; The packet and possibly packet fragments have been sent and we are
  ; waiting for a reply.  If this is a write verify operation compute
  ; the check value the user data.
  ;
  ; Note that if this machine is slow enough the server can complete the write
  ; and send back its CRC faster than we can compute it.  That value will be
  ; saved and we'll check it when this code gets through the spin wait that
  ; waits for a response.

  cmp    cmd_op, Op_Write
  jz     cmd_output_skip_crc

  ; Compute the length of the user buffer
  mov    cx, cmd_sectors_req             ; Given 512 byte blocks, compute number of bytes.
  mov    ch, cl                          ; Fast shift to mult by 256.
  xor    cl, cl                          ; Clear lower byte as part of the mult by 256.
  shl    cx, 1                           ; One more shift to get to bytes.

  ; CRC routine: Source is in DS:SI, length is in CX, DX has return value
  mov    si, cmd_user_buf_off
  mov    ds, cmd_user_buf_seg            ; Order is important here ... muck up DS last.

  cmp    cx, 4096
  ja     cmd_output_compute_fletcher

  call   calcCRC
  mov    ax, cs                               ; Restore DS
  mov    ds, ax
  mov    WORD PTR cmd_output_crc_lcl, dx      ; CRC16 value in low bytes
  mov    WORD PTR cmd_output_crc_lcl + 2, 0   ; 0 for unused high bytes
  jmp    cmd_output_skip_crc

  cmd_output_compute_fletcher:
  call   fck32
  push   ax
  mov    ax, cs                               ; Restore DS
  mov    ds, ax
  pop    ax
  mov    WORD PTR cmd_output_crc_lcl, ax      ; Low bytes
  mov    WORD PTR cmd_output_crc_lcl + 2, dx  ; High bytes

  cmd_output_skip_crc:

  mov    ax, shared_data.net_pkt_timeout
  mov    countdownTimer, ax


  cmd_output_spinwait:
  ; Now spin and wait for the response
  cmp    cmd_resp_recved, 1
  jz     cmd_output_check_result
  cmp    countdownTimer, 0
  jnz    cmd_output_spinwait

  ; Timeout ..
  cmp    cmd_retry_count, 0
  jz     cmd_output_timeout

  ; Nothing should have moved so just go back to the top of the loop and try again.


  ; SW: We need to reset the pointers and start LBA back to the start of the group
  ; and start the whole group over again.


  mov    si, curr_unit
  add    word ptr [si].unit_blocks_retries, 1
  adc    word ptr [si].unit_blocks_retries+2, 0

  dec    cmd_retry_count
  jmp    cmd_output_loop_retry_top


  cmd_output_check_result:

  ; For a standard write we just check the return code from the server.  For a
  ; write-verify we also have to compare the CRC that they computed against the
  ; one that we computed.  Even if the server reported no error, if we detect
  ; a mismatch on the final step it is an error.

  cmp    cmd_result, 0
  jnz    cmd_output_bad_result

  cmp    cmd_op, Op_Write
  jz     cmd_output_crc_good

  mov    ax, WORD PTR cmd_output_crc_lcl      ; The CRC we computed.
  cmp    ax, WORD PTR cmd_output_crc_rmt      ; The CRC from the server.
  jne    cmd_output_crc_bad
  mov    ax, WORD PTR cmd_output_crc_lcl + 2  ; The CRC we computed.
  cmp    ax, WORD PTR cmd_output_crc_rmt + 2  ; The CRC from the server.
  je     cmd_output_crc_good
  
  cmd_output_crc_bad:

  mov    cmd_result, 1
  jmp    cmd_output_bad_result


  cmd_output_crc_good:

  ; The last response was good.  Advance the global sequence number.

  ; SW: Advancing the sequence number is cool, but the pointers and start LBA are going
  ; to jump a bit too.


  mov    si, curr_unit
  mov    ax, cmd_sectors_req
  add    word ptr [si].unit_blocks_written, ax
  adc    word ptr [si].unit_blocks_written+2, 0

  call   update_local_ssc                ; Update our local Sequence, Start and Count
  jmp    cmd_output_loop_top             ; And go back to do it all again ...


  cmd_output_loop_finished:

  ; Restore rh header and segment
  ; The number of sectors read should already be in the RH.
  mov    ax, cs:rh_seg
  mov    es, ax
  mov    bx, cs:rh_off
  jmp    done


  ; Bad result means we got a response, so update the sequence number
  ; Then continue through the timeout code because both report an error.
  cmd_output_bad_result:
  mov    si, curr_unit
  inc    [si].unit_sequence

  cmd_output_timeout:
  ; Restore rh header and segment
  mov    ax, cs:rh_seg
  mov    es, ax
  mov    bx, cs:rh_off

  ; Give them a general write fault and the number of sectors written.
  ; Tell them it was a write fault.  Given this is a timeout it could
  ; be a "drive not ready" too but write fault works for both timeout
  ; and bad result.

  mov    es:[bx].rh_status, 0x800a
  mov    ax, es:[bx].rh_input_count      ; Total number of sectors -
  sub    ax, cmd_count                   ; Sectors still left to transfer
  mov    es:[bx].rh_input_count, ax      ; Successful sectors transfered.
  jmp    done




; Done: set the done bit, restore state and exit
done:
  mov    cs:cmd_active, 0
  or     es:[bx].rh_status, 0x0100

  pop    es
  pop    ds
  pop    di
  pop    si
  pop    bp
  pop    dx
  pop    cx
  pop    bx
  popf

  ; Restore prior stack.
  switchFromStack dosint

  ret




; ============================================================================
;
; Utility functions for Input and Output

setup_cmd_vars proc near

  ; Copy the user buffer address, start LBA and count from the RH and store
  ; them locally.  We will be modifying our local copies at the main loop
  ; progresses.

  mov    ax, es:[bx].rh_input_buf_off    ; User buffer offset
  mov    cmd_user_buf_off, ax
  mov    ax, es:[bx].rh_input_buf_seg    ; User buffer segment
  mov    cmd_user_buf_seg, ax
  mov    ax, es:[bx].rh_input_count      ; Sector count
  mov    cmd_count, ax


  ; What DOS are we on?  Use the RH length to determine where to read
  ; the starting LBA from as it can be either 16 or 32 bits.

  cmp    es:[bx].rh_input_rh.rh_len, 0x16
  jnz    setup_cmd_vars_1


  ; This is either an older DOS (2.x or 3.x) or DOS 4+ and the start LBA is
  ; small enough.  Read a word from the original input_start location.

  setup_cmd_vars_use_16bit_start:

  mov    ax, es:[bx].rh_input_start      ; 16 bit sector address
  mov    word ptr cmd_start, ax
  xor    ax, ax                          ; Clear the upper 16 bits.
  mov    word ptr cmd_start+2, ax
  ret


  setup_cmd_vars_1:

  ; Is this Compaq DOS 3.31 or DR DOS 6?  If so the request header is 24 bytes
  ; with the input_start field being extended to a double word.
  ; https://faydoc.tripod.com/structures/25/2597.htm

  cmp    es:[bx].rh_input_rh.rh_len, 0x18
  jnz    setup_cmd_vars_2

  mov    ax, word ptr es:[bx].rh_input_start   ; Low 16 bits
  mov    word ptr cmd_start, ax
  mov    ax, word ptr es:[bx].rh_input_start+2 ; High 16 bits
  mov    word ptr cmd_start+2, ax
  ret


  setup_cmd_vars_2:

  ; This is DOS 4.x or above and the request header length should be 0x1E.
  ; If rh_input_start is set to 0xFFFF then use rh_input_hugeStart, 
  ; otherwise go back and use rh_input_start.

  cmp    es:[bx].rh_input_start, 0xFFFF
  jnz    setup_cmd_vars_use_16bit_start

  mov    ax, word ptr es:[bx].rh_input_hugeStart   ; Low 16 bits
  mov    word ptr cmd_start, ax
  mov    ax, word ptr es:[bx].rh_input_hugeStart+2 ; High 16 bits
  mov    word ptr cmd_start+2, ax

  ret

setup_cmd_vars endp




; Update local sequence, start and count for the next loop iteration

update_local_ssc proc near

  mov    si, curr_unit
  inc    [si].unit_sequence

  ; Also bump the start LBA, decrement the count, and advance the
  ; target buffer address.  (Advancing the segment to avoid wrap around
  ; complications with the offset.)

  mov    ax, cmd_sectors_req
  add    word ptr cmd_start, ax          ; 32 bits so add with carry.
  adc    word ptr cmd_start+2, 0         ; Capture the carry bit.

  sub    cmd_count, ax                   ; Update the number of sectors left to do.

  mov    cl, 5                           ; Advance the user buffer pointer.  We do
  shl    ax, cl                          ; this by segment instead of bytes as
  add    cmd_user_buf_seg, ax            ; explained above.

  ret

update_local_ssc endp




; prepIpFlags
;
; Input:
;   paras_to_send, paras_this_pkt and fragment_offset global vars
;
; Output:  
;   BX: A word with the IP header flags and fragment offset ready to set.
;       (It still needs to be byte swapped before sending.)
;
; Other than for the output, there are so side effects from this code.
; It preserves AX so our callers have one less thing to worry about.

prepIpFlags proc near

  ; IP fragment logic - determine the more fragments flag.

  ; IP fragment handling
  ;
  ; Set a flag in the IP header if there is going to be a fragment transmitted
  ; after this packet.  (That happens when we have more sectors pending than
  ; are being sent in this specific packet.)
  ;
  ; Fragment offsets are always on an eight byte boundary so the offset field
  ; in the IP header doesn't send the low three bits.  Divide by 8 here and
  ; merge with the fragment flag.  It's not worth skipping if the fragment
  ; offset is zero as it's just some shifting and an and.

  mov    bx, paras_to_send
  cmp    paras_this_pkt, bx
  mov    bx, fragment_offset
  jl     more_fragments

  ret

  more_fragments:
  or     bx, IP_HDR_MOREFRAGS
  ret

prepIpFlags endp



; ============================================================================
;
; processArpRequest
;
; If this an ARP request for us?  If so, stash the requesting
; IP address and MAC address so that we can send a response
; under the timer tick interrupt.
;
; This is being overly thorough ...  not all of the fields that I am
; checking need to be checked.  Also, it's not performance sensitive
; as ARPs are infrequent.  If you wanted to speed it up you could
; check for the target_ip first to see if it is us before checking
; everything else.
;
; On entry
;   SI is pointing at the incoming buffer.
;   DS and ES should be set.
;
; Preconditions: Ethernet target hardware address = broadcast and EtherType = ARP
;
; ARP Checks
;   Hardware type = 1
;   Protocol type = 0x0800
;   hlen = 6
;   plen = 4
;   Op = 1
;   Target_ip = our ip

processArpRequest proc near

  ; If there is already a pending ARP request do not obliterate it.
  cmp    arp_pending, 1
  je     arp_req_exit

  mov    si, incoming_buf_p
  cmp    word ptr [si].pkt_arp_hdw_type, 0x0100
  jne    arp_req_exit
  cmp    word ptr [si].pkt_arp_prot_type, 0x0008
  jne    arp_req_exit
  cmp    [si].pkt_arp_hlen, 0x06
  jne    arp_req_exit
  cmp    [si].pkt_arp_plen, 0x04
  jne    arp_req_exit
  cmp    word ptr [si].pkt_arp_op, 0x0100
  jne    arp_req_exit
  mov    ax, word ptr shared_data.net_my_ip
  cmp    ax, word ptr [si].pkt_arp_target_ip
  jne    arp_req_exit
  mov    ax, word ptr shared_data.net_my_ip+2
  cmp    ax, word ptr [si].pkt_arp_target_ip+2
  jne    arp_req_exit

  ; It's ours ..  stash what we need for later.
  ; Fixme: this is last in wins.  Do we need to support
  ; a second pending request?

  mov    arp_pending, 1

  ; Copy the sending hardware address to the target Ethernet address
  add    si, pkt_arp_sender_ha
  mov    di, OFFSET shared_data.net_arp_resp.pkt_arp_eth_dest
  movsw
  movsw
  movsw

  ; Copy the sending hardware address and IP address.
  ; Using MOVSW so source is in DS:SI, target is in ES:DI
  mov    si, incoming_buf_p
  add    si, pkt_arp_sender_ha
  mov    di, OFFSET shared_data.net_arp_resp.pkt_arp_target_ha
  movsw
  movsw
  movsw
  movsw
  movsw

  ; And now it is ready to be sent at the next opportunity.

  arp_req_exit:
  ret

processArpRequest endp



; ============================================================================
;
; receivepacket
;
; The packet driver will call this function twice for each received packet:
;
; First call: AX=0, BX=handle, CX=packet len
;   If you can handle the packet then return an address to a buffer in ES:DI.
;   If not, ES:DI is set to 0.
;
; Second call: AX=1, BX=handle, CX=packet len, DS:SI is our buffer
;   Process the packet if it is ours, or pass it to a downstream user.
;
; If we have a downstream user we'll pretend we are the packet driver and
; give them the buffer if the packet is not exclusively for NetDrive.


receivePacket proc far

  ; Is this the first call from the packet driver?
  cmp    ax, 1
  je     receiveSecondCall
       
  ; Are we processing packets yet?
  cmp    cs:shared_data.net_pkt_recv_on, 0
  je     receive_no_thanks

  ; Packet too big?  Reject it.
  cmp    cx, ETH_FRAME_SIZE
  ja     receive_no_thanks

  ; OK, we'll take it.  Give them the buffer to copy to for the next call.
  mov    di, cs:incoming_buf_p
  mov    ax, cs
  mov    es, ax
  retf


  receive_no_thanks:
  xor    ax, ax
  mov    di, ax
  mov    es, ax
  retf


  receiveSecondCall:

  ; We are going to be here for a while and we are going to touch lots of registers.
  ; Switch to a private stack, save the registers, and setup DS.  We don't need to
  ; worry about what AX after the stack switch because we know what it was on entry
  ; and it is not needed now.

  switchToStack recvint

  push   bx
  push   cx
  push   dx
  push   bp
  push   si
  push   di
  push   ds
  push   es
  pushf

  cld

  mov    ax, cs                          ; Setup DS and DS
  mov    ds, ax
  mov    es, ax

  mov  incoming_pkt_len, cx              ; Save the incoming length for later.

  ; Increment total number of packets received.
  add    word ptr shared_data.net_c_r_total, 1
  adc    word ptr shared_data.net_c_r_total+2, 0

  ; Is this packet for us? (Same MAC address)
  mov    si, incoming_buf_p              ; Eth dest is right at the start.
  mov    di, OFFSET shared_data.net_my_mac
  mov    cx, 3
  repz   cmpsw 

  ; If you get here and zero flag is set all 3 words were compared and are equal.
  je     ourpacket

  ; Was this a broadcast packet?
  mov    si, incoming_buf_p              ; Eth dest is right at the start.
  mov    di, OFFSET eth_broadcast
  mov    cx, 3
  repz   cmpsw 

  ; This is not a broadcast packet; send it downstream.
  jne     receive_check_downstream_bounce

  ; The only broadcast packet we care about is ARP.
  mov    si, incoming_buf_p              ; Eth dest is right at the start.
  cmp    word ptr [si].pkt_arp_eth_type, ETH_TYPE_ARP
  jne    receive_check_downstream_bounce

  ; processArpRequest modifies ax but we don't need it anymore.
  call   processArpRequest
  jmp receive_check_downstream           ; Bounce jump not needed here.


ourpacket:
  add    word ptr shared_data.net_c_r_our_mac, 1
  adc    word ptr shared_data.net_c_r_our_mac+2, 0

  ; Was it ARP directly to us?
  mov    si, incoming_buf_p
  cmp    word ptr [si].pkt_arp_eth_type, ETH_TYPE_ARP
  jne    receiveIpCheck

  call   processArpRequest
  ; Fall through

  ; This little hack is to help the code generation of the assembler, as the
  ; jump to receive_check_downstream is too far for a je or jne instruction.
  receive_check_downstream_bounce:
  jmp    receive_check_downstream


receiveIpCheck:

  ; Do some quick checks to see if it's IPv4 and UDP.  If it is then we
  ; can check to see if it is to us and from the server.  This order of
  ; checking allows us to bail out quickly if it's not for this driver.

  ; EtherType is IP (0x0800)
  cmp    word ptr [si].pkt_ip_eth_type, ETH_TYPE_IP
  jne    receive_check_downstream_bounce

  ; IP version is 0x04
  mov    al, [si].pkt_ip_vers_hlen
  and    al, 0xf0
  cmp    al, 0x40
  jnz    receive_check_downstream_bounce

  cmp    [si].pkt_ip_protocol, IP_UDP_PROTOCOL
  jne    receive_check_downstream_bounce

  mov    ax, word ptr shared_data.net_my_ip
  cmp    ax, word ptr [si].pkt_ip_dest
  jne    receive_check_downstream_bounce
  mov    ax, word ptr shared_data.net_my_ip+2
  cmp    ax, word ptr [si].pkt_ip_dest+2
  jne    receive_check_downstream_bounce

  mov    di, curr_unit

  mov    ax, word ptr [di].unit_server_ip
  cmp    ax, word ptr [si].pkt_ip_src
  jne    receive_check_downstream_bounce
  mov    ax, word ptr [di].unit_server_ip+2
  cmp    ax, word ptr [si].pkt_ip_src+2
  jne    receive_check_downstream_bounce


  ; Checking the UDP port is a bit more involved, as the UDP packet is
  ; not in a fixed location because of possible IP header options.
  ; The hlen field represents the header length in 4 byte quantities.
  ; Read the number of bytes for the IP header and compute an offset
  ; to the start of the UDP header.

  xor    dx, dx
  mov    dl, [si].pkt_ip_vers_hlen
  and    dl, 0x0f
  shl    dx, 1                           ; DX now has the IP header length in words
  shl    dx, 1                           ; DX now has the IP header length in bytes
  add    dx, ETH_HDR_LEN                 ; DX now has an offset to the UDP header.

  ; The source port needs to match the server port and the destination
  ; port needs to match our local port.  (And remember, network byte order.)

  add    si, dx                          ; Skip past Eth and IP headers.

  lodsw                                  ; pkt_udp_src
  xchg   ah, al
  mov    di, curr_unit
  cmp    ax, [di].unit_server_port
  jne    receive_check_downstream_bounce

  lodsw                                  ; pkt_udp_dest
  xchg   ah, al
  cmp    ax, shared_data.net_my_port
  jne    receive_check_downstream_bounce

  ; This packet is definitely for us; don't pass it to the next user.
  ; Do this by jumping to receive_exit if we want to leave.

  ; Ok, everything matches.  Verify the IP checksum
  mov    si, incoming_buf_p
  call   computeIpChecksum
  cmp    ax, 0
  jne    receive_exit_bounce


  ; UDP checksums are optional.  If it is 0 then don't check it.

  ; Get to the IP header, then extract the length and get to the UDP header.
  mov    si, incoming_buf_p
  add    si, pkt_ip_vers_hlen
  xor    ax, ax
  mov    al, byte ptr [si]
  and    al, 0x0f
  shl    ax, 1
  shl    ax, 1
  add    si, ax
  mov    ax, [si+pkt_udp_chksum]

  cmp    ax, 0
  je     receiveSkipUdpChksum

  ; The UDP checksum is set so check it.  
  mov    si, incoming_buf_p
  xor    ax, ax
  call   computeUdpChecksum
  cmp    ax, 0
  jne    receive_exit_bounce

  receiveSkipUdpChksum:

  ; Checksum was good.  Bump the counter of UDP packets destined for us.
  add    word ptr shared_data.net_c_r_our_udp, 1
  adc    word ptr shared_data.net_c_r_our_udp+2, 0



  ; The next sequence of checks verifies that the received response has
  ; at least a full command header and that that the session and sequence
  ; number match.  If everything checks out process the packet now because
  ; another incoming packet will obliterate this packet.  (ReadAhead doesn't
  ; need an exact match on the sequence number, so it will do its own checking.)
  ;
  ; If it is a good read copy the payload too.  (You can only copy the
  ; payload if you know there is a user buffer setup waiting for it.)

  ; Setup so we can directly access the UDP portion of the packet.
  ; Then check the fields strictly to ensure this is what we asked for.
  mov    bx, incoming_buf_p
  add    bx, pkt_udp_src
  add    bx, dx


  ; Verify that we received something that at least has a full command header.
  mov    ax, [bx].pkt_udp_len
  xchg   al, ah                          ; Never forget, network byte order for UDP fields.
  cmp    ax, UDP_ND_LEN
  jb     receive_exit_bounce

  ; Fixme: Should we check the protocol version here just to be complete?


  ; Does the session match?
  mov    si, curr_unit
  mov    ax, [si].unit_session
  cmp    ax, [bx].pkt_nd_session
  jne    receive_exit_bounce

  ; Before checking the sequence number see if this is a ReadAhead packet.
  ; That code will do its own checks on the sequence number.
  cmp    [bx].pkt_nd_op, Op_ReadAheadPkt
  jne    receive_not_readahead
  call   receive_ReadAhead

  ; Another cheap hack to improve code size and performance.
  receive_exit_bounce:
  jmp    receive_exit


  receive_not_readahead:
  ; Ensure the sequence number, operation, start sector, and number
  ; of sectors is an exact match.

  mov    ax, [si].unit_sequence
  cmp    ax, [bx].pkt_nd_sequence
  jne    receive_exit_bounce

  mov    al, cmd_op
  cmp    al, [bx].pkt_nd_op
  jne    receive_exit_bounce

  mov    ax, word ptr cmd_start
  cmp    ax, word ptr [bx].pkt_nd_start
  jne    receive_exit_bounce
  mov    ax, word ptr cmd_start+2
  cmp    ax, word ptr [bx].pkt_nd_start+2
  jne    receive_exit_bounce

  mov    ax, cmd_sectors_req
  cmp    ax, [bx].pkt_nd_count
  jne    receive_exit_bounce


  ; One last check - are we actually waiting for something?  (Is a DOS read
  ; or write active in this device driver?)  If so then process this packet.
  ; Otherwise, this is a duplicate packet and there is no point in processing
  ; it.  It is a small timing ; window but we need to check it.

  cmp    cmd_active, 1
  jne    receive_exit_bounce
  cmp    cmd_resp_recved, 0
  jne    receive_exit_bounce


  ; Everything matches and we are expecting it.
  ;
  ; Copy the return code and indicate that the response was received.
  ; If this is a bad return code then we are done.

  mov    cmd_resp_recved, 1
  mov    al, [bx].pkt_nd_result
  mov    cmd_result, al
  cmp    al, 0
  jne    receive_exit_bounce

  ; Write with verify has extra work to do.
  cmp    cmd_op, Op_Write_Verify
  je     receive_write_verify

  ; Is this a plain write?  If so then there is nothing else to do.
  cmp    cmd_op, Op_Write
  je     receive_exit_bounce

  ; This is a successful read.  Copy the payload, but only copy what we
  ; requested.  If the number of received bytes doesn't match the expected
  ; bytes then we mark this as bad.

  mov    ax, [bx].pkt_udp_len
  xchg   al, ah                          ; Never forget, network byte order for UDP fields.
  sub    ax, UDP_ND_LEN                  ; This is safe; we checked for a minimum length earlier.

  mov    dx, cmd_sectors_req             ; Number of sectors we requested on the last pass.
  mov    cl, 9
  shl    dx, cl                          ; Times 512.

  cmp    ax, dx
  je     receive_copy                    ; All good, copy the payload.

  ; Mark the command as bad and exit
  mov    cmd_result, 1
  jmp    receive_exit


  receive_copy:

  ; Using MOVSW so source is in DS:SI, target is in ES:DI

  lea    si, [bx+pkt_nd_data]
  mov    es, cmd_user_buf_seg
  mov    di, cmd_user_buf_off
  mov    cx, ax                          ; Payload length from above
  shr    cx, 1                           ; Divide by two for word moves
  rep    movsw

  and    ax, 1
  jz     receive_exit
  movsb                                  ; Move the last odd byte.
  jmp    receive_exit


  receive_write_verify:
  ; Instead of getting back what we wrote, we get a 16 bit CRC computed
  ; by the other side after they write and read back the data.  Copy
  ; the received CRC to a safe place and mark the command as completed.
  ; The cmd_output routine will do the final check to ensure the local
  ; and remote CRCs matched.
  ;
  ; Making the output routine do the comparison saves us from when the
  ; server is far faster than the DOS machine and responds faster than
  ; the DOS machine can compute the CRC.  We used to just disable
  ; interrupts until the DOS machine was done; that worked but this
  ; is more elegant and prevents lost timer tick interrupts.

  ; Verify they sent us a CRC in the length.

  mov    ax, [bx].pkt_udp_len
  xchg   al, ah                          ; Never forget, network byte order for UDP fields.
  sub    ax, UDP_ND_LEN                  ; This is safe; we checked for a minimum length earlier.
  cmp    ax, 4
  jne    receive_write_verify_bad_payload

  ; Save the CRC sent to us.  It will be checked after the spin wait loop exits.
  mov    ax, word ptr [bx].pkt_nd_data
  mov    WORD PTR cmd_output_crc_rmt, ax
  mov    ax, word ptr [bx].pkt_nd_data + 2
  mov    WORD PTR cmd_output_crc_rmt + 2, ax
  jmp    receive_exit

  receive_write_verify_bad_payload:
  ; Somehow we got a mal-formed packet.  Force the return code to bad and exit.
  mov    [bx].pkt_nd_result, 1
  jmp    receive_exit


  receive_check_downstream:
  ; Is there somebody waiting for this packet?
  cmp    handles_in_use, 0
  je     receive_exit
  call   receive_send_downstream


  receive_exit:
  popf
  pop    es
  pop    ds
  pop    di
  pop    si
  pop    bp
  pop    dx
  pop    cx
  pop    bx

  switchFromStack recvint

  retf

receivePacket endp



receive_ReadAhead proc near

  ; On entry BX points at the packet UDP header.  Don't alter it.

  ; Every active command sets the active unit number (curr_unit), and to
  ; get to this point you have to match the server, port, and session of
  ; the active command.  Old readahead packets from a different unit
  ; arriving late would not have made it this far.
  ;
  ; Validate that the sequence number in the packet is equal to or greater
  ; than the sequence number when DOS issued a read to the device driver.
  ; That protects us against old-readahead data coming in when we are doing
  ; back-to-back reads on the same unit.  Later sequence numbers are ok,
  ; as they will be using the same buffer the DOS caller provided.  (When
  ; the DOS caller ; starts a new read we update the read-ahead variables.)
  ;
  ; This check can fail if the command sequence number wraps during a read
  ; operation.  That's fine, it will just disable read-ahead caching for
  ; the duration of that read command and resume on the next one.

  mov    ax, word ptr [bx].pkt_nd_sequence
  cmp    ax, ra_seq_start
  jb     receive_ReadAhead_exit

  
  ; Is the payload length what we expect?

  mov    ax, [bx].pkt_udp_len
  xchg   al, ah                          ; Never forget, network byte order for UDP fields.
  sub    ax, UDP_ND_LEN                  ; This is safe; we checked for a minimum length earlier.

  mov    dx, [bx].pkt_nd_count           ; Multiply the number of blocks by 512
  mov    cl, 9
  shl    dx, cl

  cmp    ax, dx
  jne    receive_ReadAhead_exit


  ; This is our readahead.  Setup to copy the first block in the packet.
  mov    ra_receive_index, 0

  receive_ReadAhead1:

  ; The user issued a read, and the starting LBA is in ra_lba_start (32 bits).
  ; The count is in ra_lba_count (16 bits).  The user buffer is in ra_buf_seg and ra_buf_off.

  ; Using MOVSW so source is in DS:SI, target is in ES:DI.

  ; Position to the correct place in the packet.  (Either offset 0 or 512.)
  lea    si, [bx+pkt_nd_data]
  mov    ax, ra_receive_index
  mov    cx, 9
  shl    ax, cl
  add    si, ax

  ; Figure out where we are going to copy the first block in the packet to.
  ; The packet has pkt_nd_start, which is a 32 bit LBA start address.
  ; Compute the difference between that and ra_lba_start to get a sector
  ; offset and multiply that by 512 to get the target offset into the user buffer.

  ; The difference always fits in 16 bits so there is no need to to the
  ; high word with the sbb, which uses the carry flag to fix the upper word.
  mov    ax, word ptr [bx].pkt_nd_start
  sub    ax, word ptr ra_lba_start
  ;mov    ax, word ptr [bx].pkt_nd_start+2
  ;sbb    ax, word ptr ra_lba_start+2


  ; AX now has the number of block from the start of the originally supplied
  ; user buffer to the first block in this packet.  Bump that number if we
  ; are processing the second block in a packet.
  add    ax, ra_receive_index

  ; If this block doesn't fit in the originally supplied user buffer then somebody
  ; screwed up - discard the packet.
  cmp    ra_lba_count, ax
  jbe    receive_ReadAhead_exit

  ; If this block is beyond what we can mark in the readahead bitmap then
  ; somebody screwed up - discard the packet.
  cmp    ax, RA_MAX_BLOCK
  ja     receive_ReadAhead_exit

  ; Save AX temporarily so we can use it to turn on the bit in our readahead bitmap.
  push   ax

  ; Multiply AX by 32 to get the number of paragraphs that we are going to
  ; skip.  Then add that to ra_buf_seg to get the starting segment to copy
  ; into.  We don't ever mess with the offset so use ra_buf_off directly.

  mov    cl,5
  shl    ax,cl
  mov    di, ra_buf_off
  add    ax, ra_buf_seg
  mov    es, ax
  mov    cx, 256                         ; Copy!
  rep    movsw

  ; Now we have to turn on the appropriate bit in the ra_slot_valid map.

  ; Restore AX (the block offset) but also save BX, as it has a pointer
  ; into the packet that we might need again.
  pop    ax
  push   bx

  ; Figure out which byte of ra_slot_valid to get and load it into BX
  mov    cx, ax
  shr    cx, 1
  shr    cx, 1
  shr    cx, 1
  mov    bx, OFFSET ra_slot_valid
  add    bx, cx

  ; Isolate the bit in AX
  and    ax, 0x7
  mov    cx, ax
  mov    ax, 1
  shl    ax, cl
  or     byte ptr [bx], al

  pop    bx


  ; Loop around again
  inc    ra_receive_index
  mov    ax, ra_receive_index
  cmp    ax, [bx].pkt_nd_count
  jb     receive_ReadAhead1

  ; We are done!
  receive_ReadAhead_exit:
  ret

receive_ReadAhead endp



receive_send_downstream proc near

  ; Find the handle that will handle this, if there is one.
  mov    si, incoming_buf_p              ; Get the EtherType
  mov    dx, [si].pkt_arp_eth_type
  mov    bx, OFFSET handles              ; Search starts at slot 0.

  receive_handle_search_top:

    cmp   [bx].handle_in_use, 0
    je    receive_handle_check_next

    ; If the handle is in use and it matches either the exact EtherType passed
    ; in or the catch-all value, then return with bx pointing at the handle.
    cmp   [bx].handle_type, 0
    je    receive_handle_found
    cmp   [bx].handle_type, dx
    je    receive_handle_found

    receive_handle_check_next:

    ; This slot is not in use or there is no match.  Advance to the next slot.
    ; If there is no next slot, set the carry flag.

    add   bx, size handle_rec
    cmp   bx, OFFSET end_handles
    jb    receive_handle_search_top

    ; Ran out of entries to search.  Early return.
    ret


  receive_handle_found:

  ; First call; tell them the length.  Protect BX because it is critical to us.
  push   bx
  mov    ax, 0
  mov    cx, incoming_pkt_len
  call   [bx].receiver
  pop    bx

  ; If they passed back ES:DI == 0:0 we are done.
  mov    ax, es
  or     ax, di
  jz     receive_send_downstream_exit

  receive_copy_for_downstream:

  ; Save ES:DI (their buffer) for later when we have to return it in DS:SI.
  push   es
  push   di

  ; Source is our packet (DS:SI).  DS is already set.
  mov    si, incoming_buf_p

  ; Setup for moving a word at a time.  Preserve CX so we can see if
  ; there is an odd byte to move.
  mov    cx, incoming_pkt_len          ; Paranoid, but safe - they might have touched CX.
  push   cx
  shr    cx, 1
  rep    movsw
  pop    cx
  and    cx, 1
  jz     receive_downstream_copy_done
  movsb

  receive_downstream_copy_done:

  mov    ax, 1
  mov    cx, incoming_pkt_len
  pop    si                            ; The user expects their es:di in ds:si now.
  pop    ds
  call   cs:[bx].receiver


  receive_send_downstream_exit:
  ret

receive_send_downstream endp





; ============================================================================
;

ifdef CHKSUM_TESTING

testIpChksum proc far
       call computeIpChecksum
       retf
testIpChksum endp

testUdpChksum proc far
       call computeUdpChecksum
       retf
testUdpChksum endp

endif



; Compute Checksum routines
;
; When constructing a packet set the checksum field to zero first.
; This will give you the value to place in the checksum field.
;
; When checking a packet the value computed here should be 0.
;



; computeIpChecksum
;
; Usually IP headers are just 20 bytes, but who knows if something set an
; IP header option somewhere.  So be smart and use the actual length from
; the IP header to determine the length of it.
;
; Input:
;   DS:SI has an offset to the packet start.  (The Eth header.)
;
; Output:
;   AX returns the checksum
;   DX is untouched.  Make sure DX stays untouched.
;
; BX and CX are destroyed.


computeIpChecksum proc near

       ; Skip to the start of the IP header.
       add   si, ETH_HDR_LEN

       ; Extract the length nibble from the IP header.
       mov   cl, byte ptr [si]
       and   cx, 0x0f

       ; Clear the carry bit and result register.
       clc
       xor   bx, bx

       computeIpChecksumLoop:
       lodsw
       adc   bx, ax
       lodsw
       adc   bx, ax
       loop  computeIpChecksumLoop

       adc   bx, 0     ; Capture any extra carry

       not   bx
       mov   ax, bx

       ret

computeIpChecksum endp



; computeUdpChecksum
;
; Compute the UDP checksum for a packet, which includes the IP pseudo-header.
; This implies that you can not call this until the IP and UDP headers of the
; packet are populated.
;
; Options in the IP header will be properly skipped.
;
; Input:
;   DS:SI points to the start of an incoming our outgoing packet.
;   AX is 0 or a partial checksum.  (If 0, the UDP header and payload is
;      checksummed in this routine.  It not 0, we assume that portion was
;      already checksummed and the partial result is in AX.)
;
; Output:
;   AX has the final UDP checksum.
;   DX is untouched.  Make sure DX stays untouched.

computeUdpChecksum proc near

       push  ax

       ; Clear the carry bit.
       clc

       ; Save SI so we can use it again later
       push  si

       ; Start with the IP source and destination (4 16 bit words).
       add   si, pkt_ip_src

       lodsw
       mov   bx, ax    ; Use mov instead of add to save on zeroing out bx
       lodsw
       adc   bx, ax
       lodsw
       adc   bx, ax
       lodsw
       adc   bx, ax
       adc   bx, 0     ; Capture any extra carry

       ; Next the protocol and the byte of 0's.  We already know it is
       ; UDP otherwise we wouldn't be here.
       xor   al, al
       mov   ah, IP_UDP_PROTOCOL
       add   bx, ax
       adc   bx, 0     ; Capture any extra carry

       ; Compute where the UDP header starts so that we can get the length
       ; field from it.
       pop   si
       add   si, ETH_HDR_LEN

       ; Get the length of the IP header in bytes.
       xor   ax, ax
       mov   al, byte ptr [si]
       and   al, 0x0f
       shl   ax, 1
       shl   ax, 1

       ; Add the length of the IP header to get to the start of the UDP header.
       add   si, ax

       ; Load the length field from the UDP header.
       mov   ax, [si+pkt_udp_len]
       add   bx, ax
       adc   bx, 0     ; Capture any extra carry

       ; At this point you are done with the pseudo-header.


       ; AX has a byte swapped UDP length.  Move it CX and swap the bytes to get
       ; the actual length.  Then subtract 8 so that we get the payload length
       ; and save it in CX.
       mov   cx, ax
       xchg  cl, ch


       ; Checksum the 8 bytes of the UDP header, then subtract its length from CX.

       clc

       lodsw
       adc   bx, ax
       lodsw
       adc   bx, ax
       lodsw
       adc   bx, ax
       lodsw
       adc   bx, ax
       adc   bx, 0

       sub   cx, 8
       clc


       ; If we were provided a partial checksum on entry skip scanning the UDP payload.
       ; Otherwise, continue checksumming through the UDP payload.
       pop   ax
       cmp   ax, 0
       jnz   computeUdpChecksum_1

       ; On entry BX and CX are already set up for us.  On return AX will have
       ; the cumulative checksum so clear BX or we'll wind up applying it twice.
       call  computeUdpDataChecksum
       xor   bx, bx 

       computeUdpChecksum_1:
       adc   bx, ax
       adc   bx, 0
       
       not   bx
       mov   ax, bx

       ret

computeUdpChecksum endp




; Compute a partial checksum over only the user data.
;
; Input:
;   BX is a partial checksum or is 0
;   DS:SI points at the user data.
;   CX is the length of the user data.
;
; Output:
;   AX has the new partial checksum
;   DX is untouched.  Make sure DX stays untouched.

computeUdpDataChecksum proc near

       ; Save cx for later use.
       push  cx

       ; We loop a word at at time.  Loop unroll 8x for better performance.
       shr   cx, 1  ; # of words
       shr   cx, 1
       shr   cx, 1
       shr   cx, 1  ; Divided by 8.

       ; Skip the loop unrolled part if there is not enough data.
       jcxz  computeUdpDataChecksum_2

       clc        ; Clear the carry bit in case it was set during this ptr math

       computeUdpDataChecksum_1:
       lodsw
       adc   bx, ax
       lodsw
       adc   bx, ax
       lodsw
       adc   bx, ax
       lodsw
       adc   bx, ax
       lodsw
       adc   bx, ax
       lodsw
       adc   bx, ax
       lodsw
       adc   bx, ax
       lodsw
       adc   bx, ax
       loop  computeUdpDataChecksum_1

       adc   bx, 0     ; Capture any extra carry

       computeUdpDataChecksum_2:
       ; Any words left to do?
       pop   cx
       push  cx

       shr   cx, 1
       and   cx, 7
       jz    computeUdpDataChecksum_4

       ; Checksum up to 7 words
       clc
       computeUdpDataChecksum_3:
       lodsw
       adc   bx, ax
       loop  computeUdpDataChecksum_3

       adc   bx, 0     ; Capture any extra carry

       computeUdpDataChecksum_4:
       ; Check if we have an odd byte ...
       pop   cx
       and   cx, 1
       jz    computeUdpDataChecksum_not_odd

       clc
       
       lodsw
       xor   ah, ah
       add   bx, ax

       adc   bx, 0     ; Capture any extra carry

       computeUdpDataChecksum_not_odd:

       mov   ax, bx
       ret

computeUdpDataChecksum endp






; setEthIpHeaders
;
; Sets the Ethernet and IP headers for the outgoing packet.
;
; Input:
;   BX = IP flags and Fragment offset field, precomputed by the caller.
;   DX = payload length.  (UDP data and UDP header, if present in this packet.)
;        DX is not altered because it will needed by the caller again shortly.
;
; Output:
;   DX (the incoming payload length) is untouched.  Make sure DX stays untouched.
;
; Side effects:
;   This always writes to our one outgoing packet.

setEthIpHeaders proc near

       ; we are going to use movsw and stosw and walk through the packet in
       ; order.  Source data is in DS:SI and the target is in ES:DI.


       mov   di, outgoing_buf_p              ; Set the target (ES:DI)
       mov   si, curr_unit                   ; Copy next hop MAC to Ethernet dest
       add   si, unit_next_hop_mac
       movsw
       movsw
       movsw

       mov   si, OFFSET shared_data.net_my_mac ; Copy our MAC to Ethernet source
       movsw
       movsw
       movsw

       mov   ax, ETH_TYPE_IP                 ; EthType
       stosw


       ; Ip Header

       mov   ax, 0x0045                      ; IP Vers/Hlen and Service type (byte swapped)
       stosw

       mov   ax, dx                          ; DX has the payload length
       add   ax, IP_HDR_LEN                  ; Add IP Header to the payload length
       xchg  al, ah                          ; Byteswap because network byte order
       stosw

       ; Ident field handling.  Byte-swap and write it, then increment only if
       ; the more fragments field is set to 0.
       mov   ax, ip_ident
       xchg  al, ah
       stosw
       test  bx, IP_HDR_MOREFRAGS
       jnz   skip_ident_increment
       inc   ip_ident                        ; Increment ident because this is a new packet.
       skip_ident_increment:

       xchg  bh, bl                          ; Byteswap and write the flags and fragment offset word
       mov   ax, bx
       stosw
       
       mov   ax, 0x11FF                      ; Protocol and TTL (255) (byte swapped)
       stosw

       xor   ax, ax                          ; Checksum (zero for now, to be filled in soon)
       stosw

       mov   si, OFFSET shared_data.net_my_ip ; Our IP address to SRC IP address
       movsw
       movsw

       mov   si, curr_unit                   ; Copy server IP address to target IP address.
       add   si, OFFSET unit_server_ip
       movsw
       movsw

       ; Compute the IP header checksum.

       mov   si, outgoing_buf_p
       call  computeIpChecksum
       mov   si, outgoing_buf_p
       mov   [si].pkt_ip_chksum, ax

       ret

setEthIpHeaders endp




; setUdpHeader
;
; Sets the fields of the UDP header, including doing the checksum caclulation.
;
; Only call this when sending a packet with a UDP header.  You will not call
; this when sending an IP fragment.
;
; Input:
;   DX is the payload length, including the UDP header.
;   AX is a partial UDP checksum from the UDP payload, or 0.  (Set to 0
;      if you want the UDP payload checksummed as part of this processing.)
;
; Output:
;   DX (the incoming payload length) is untouched.  Make sure DX stays untouched.

setUdpHeader proc near

       push  ax                              ; Save AX for later

       mov   bx, outgoing_buf_p
       lea   di, [bx].out_udp_start          ; Set the target (ES:DI)

       ; UDP Header - source port, target port, length and checksum fields.

       mov   ax, shared_data.net_my_port     ; Byte swapped source port
       xchg  al, ah
       stosw

       mov   si, curr_unit
       add   si, OFFSET unit_server_port     ; Set the source (DS:SI)

       ; si is pointing at unit_server_port (which is byte swaped)
       lodsw
       xchg  al, ah
       stosw

       ; Compute the total UDP length (header + payload) and store a byte
       ; swapped version in the UDP header.  Save the unswapped version
       ; for later in DX.

       mov   ax, dx
       xchg  al, ah                          ; Byte swap the length to store in the header.
       stosw

       ; Set the UDP checksum to zero for now.
       xor   ax, ax
       stosw

       ; Compute the UDP checksum.

       ; If AX had a partial checksum, computeUdpChecksum will use it.  If it was 0 then it
       ; is harmless.  No need to set the length, computeUdpChecksum will get it from the
       ; UDP header in the packet.
       mov   si, outgoing_buf_p
       pop   ax
       call  computeUdpChecksum

       ; If we came up with a zero for the checksum then change it to 0xFFFF so that
       ; the other side knows we did the work, and that we didn't just ignore setting
       ; the checksum value.  (computeUdpChecksum does not do this step because it is
       ; used both on the send path to compute a checksum and on the receive path to
       ; validate a checksum.)

       cmp   ax, 0
       jnz   setUdpHeader1
       mov   ax, 0xFFFF

       setUdpHeader1:
       mov   si, outgoing_buf_p
       mov   [si].out_udp_start.pkt_udp_chksum, ax

       ret

setUdpHeader endp



; sendPacket
;
; Calls the packet driver to send the formed packet on the wire.
;
; Input:
;   CX = total packet length, including Eth, IP and UDP headers.

sendPacket_di  dw ?                          ; Local variable for sendPacket: delayIncrement
sendPktCounter dw 0                          ; How many good sends have we had in a row?

sendPacket proc near

       ; On a send error we will increment the sendPckDelay by this amount.
       mov   sendPacket_di, 1

       ; Sending a packet:
       ;   AH = 4, CX = len (min 60), DS:SI = packet addr (DS already set)

       mov   sendAttempts, 5 

       sendPacket_top:
       mov   ah, 4

       ; Runt packet?
       cmp   cx, ETH_FRAME_MIN               ; Min packet size is 60 bytes
       jae   sendPacketNotRunt               ; If greater than or equal proceed.
       mov   cx, ETH_FRAME_MIN

       sendPacketNotRunt:
       mov   si, outgoing_buf_p

       ; Push dx and pop it because the driver will communicate an error code in dh,
       ; and we need dx preserved for the UDP packet length.

       push  dx
       call  doPacketInterrupt
       pop   dx

       jnc   sendPacket_end

       ; Carry flag was set so the packet driver is not happy.
       ;
       ; First, assume it is not happy because we are sending packets to it too quickly.
       ; Each time this happens increment net_pkt_send_dly, until it hits a max.  Do this only
       ; once per failure.
       ;
       ; Then just do a fixed 10ms delay before trying again.

       cmp   shared_data.net_user_send_dly, 0xffff  ; User forced a number; do not alter it.
       jne   sendPacket_1

       cmp   shared_data.net_pkt_send_dly, 160 ; Max send penalty should never go above 10ms.
       jae   sendPacket_1
       mov   ax, sendPacket_di
       add   shared_data.net_pkt_send_dly, ax
       mov   sendPacket_di, 0                  ; Set this to zero so we don't bump it again on this particular packet.

       sendPacket_1:
       mov   delayParm, 160
       call  delay

       add   word ptr shared_data.net_c_send_errs, 1
       adc   word ptr shared_data.net_c_send_errs+2, 0
       dec   sendAttempts
       cmp   sendAttempts, 0
       jnz   sendPacket_top

       ; If we run out of attempts just fall through and return.
       ; Eventually a timeout will cause a retry.

       sendPacket_end:

       ; If this was a clean send (no retries) and the net_pkt_send_dly is not
       ; fixed then try an experiment where we reduce the delay.  At worst
       ; case it will fail and we put it back up again.  This keeps it from
       ; degrading to the worst case without ever recovering.

       cmp   shared_data.net_pkt_send_dly, 0   ; Running fine, can't reduce the delay.
       je    sendPacket_end1
       cmp   sendPacket_di, 0                  ; This specific send failed, so skip the experiment.
       je    sendPacket_end1
       cmp   shared_data.net_user_send_dly, 0xffff  ; User forced a number; do not alter it.
       jne   sendPacket_end1

       inc   sendPktCounter
       cmp   sendPktCounter, 200               ; Less than 200 successful sends, do nothing.
       jb    sendPacket_end1
       mov   sendPktCounter, 0
       dec   shared_data.net_pkt_send_dly      ; Ok, see if things have improved.

       sendPacket_end1:
       ret

sendPacket endp


; delay
;
; Sometimes we need a short delay that is less than a BIOS timer tick.  We'll
; do that by reading the 8253 directly.
;
; NetDrive.exe does the work to figure out if channel 0 of the 8253 is in
; mode 2 or mode 3, and it sets a delay constant for us.  That delay constant
; is 1/10th of a millisecond.
;
; Call this routine by setting delayParm to some number of 1/10th millisecond
; increments to wait.
;
; On a slow system each iteration of the loop will take around 120 clock cycles,
; which at 4.77Mhz is around 25 microseconds  Our minimum delay is 62 microseconds
; (1/10th ms) so we can get through this code ; with one or two spins through the
; loop even on a slow system.  On faster systems it will be much quicker.

TIMER_CONTROL_PORT     equ 0x43
TIMER_CH0_DATA_PORT    equ 0x40

delay proc near

  cmp   delayParm, 0
  je    delay_early_exit

  delay_1:

  push  ax
  push  di
  push  si

  ; Latch and read the counter
  pushf
  cli
  xor   al, al
  out   TIMER_CONTROL_PORT, al
  in    al, 0x61
  in    al, TIMER_CH0_DATA_PORT
  xchg  al, ah
  in    al, 0x61
  in    al, TIMER_CH0_DATA_PORT
  popf
  xchg  al, ah

  mov   di, ax

  delay_loop:

    ; Latch and read the counter
    pushf
    cli
    xor   al, al
    out   TIMER_CONTROL_PORT, al
    in    al, 0x61
    in    al, TIMER_CH0_DATA_PORT
    xchg  al, ah
    in    al, 0x61
    in    al, TIMER_CH0_DATA_PORT
    popf
    xchg  al, ah

    mov   si, di
    sub   si, ax
    cmp   si, shared_data.net_one_10th_ms
    jb    delay_loop

    dec   delayParm
    jnz   delay_loop

  pop   si
  pop   di
  pop   ax

  delay_early_exit:
  ret

delay endp



; Timer interrupt routine
;
; If the countdown timer is active (greater than zero) decrement it.  This
; is used to detect timeouts.  We only have one countdown timer.
;
; If there is an ARP request pending update the prebuilt ARP response packet
; and send it out.
;
;
; 3Com PCI packet driver notes:
;
; This packet driver is extremely picky.  You can't respond to ARP under the
; receive interrupt.  You must chain to the other interrupts first via the
; pushf and call and then iret from here.  You can't do this under the BIOS
; tick interrupt.  But this specific set of code seems to work.
;
; In previous code that works everywhere else we send a response to the ARP
; request, and then chain by doing a far jmp to the next interrupt handler.
; That doesn't work here.

timerInt proc far

  ; This pushf is here so that the thing that we call can do an IRET to
  ; return, as it expects.  (Our normal pattern is to pushf, change a flag
  ; and then popf later ... you won't see that here.)
  pushf
  call   cs:[timerOrigInt]

  cmp    cs:countdownTimer, 0
  jz     timerInt_checkArpPending
  dec    cs:countdownTimer

  timerInt_checkArpPending:
  cmp    cs:arp_pending, 0
  jz     timerInt_chain_only


  ; Switch to a private stack first.
  switchToStack timerint

  push   bx
  push   cx
  push   dx
  push   bp
  push   si
  push   di
  push   ds
  push   es

  ; Reestablish DS
  mov    ax, cs
  mov    ds, ax

  ; ARP packets are small so they are always runt packets.  Set the
  ; packet length to the minimum of 60 (0x3c) to avoid offending anybody.

  ; Sending a packet: AH = 4, CX = len (min 60), DS:SI = packet addr (DS already set)

  mov    sendAttempts, 3

  timerInt_send_packet:
  mov    ah, 4
  mov    cx, 0x3c
  mov    si, OFFSET shared_data.net_arp_resp
  call   doPacketInterrupt

  jnc    timerInt_packet_sent

  ; Carry flag was set so the packet driver is not happy.

  ; Retry the send.  This should rarely happen in while we are under
  ; the timer interrupt.  The delay here won't screw up the timer ticks
  ; because ints are usually still enabled while we are spinning.

  timerInt_delay:
  mov    delayParm, 160
  call   delay

  add    word ptr shared_data.net_c_send_errs, 1
  adc    word ptr shared_data.net_c_send_errs+2, 0
  dec    sendAttempts
  cmp    sendAttempts, 0
  jnz    timerInt_send_packet

  ; If we run out of attempts just fall through and return.
  ; This will leave it pending and not update the sent counter.
  ; Maybe the problem will clear up on the next attempt.
  jmp    timerInt_end

  timerInt_packet_sent:
  mov    arp_pending, 0
  add    word ptr shared_data.net_c_s_arp_resp, 1
  adc    word ptr shared_data.net_c_s_arp_resp+2, 0

  timerInt_end:
  pop    es
  pop    ds
  pop    di
  pop    si
  pop    bp
  pop    dx
  pop    cx
  pop    bx

  ; Restore prior stack.
  switchFromStack timerint

  timerInt_chain_only:
  iret

timerInt endp



; doPacketInterrupt
;
; This routine doesn't alter registers.  But who knows what the
; packet driver will do; check the function you are invoking to
; find out.


doPacketInterrupt proc near
  int 0x60
  ret
doPacketInterrupt endp



; ============================================================================
;
; Our lightweight packet driver ...
;
; Aside from possible bugs, this looks and behaves like a packet driver.
; All packets not explicitly processed by the main driver will be passed here,
; including ARP and broadcast traffic.  Downstream programs should not be
; able to detect that they are being filtered.

even

function_table label word
  dw  f_not_implemented     ;0
  dw  f_driver_info         ;1
  dw  f_access_type         ;2
  dw  f_release_type        ;3
  dw  f_send_pkt            ;4
  dw  f_terminate           ;5
  dw  f_get_address         ;6
  dw  f_reset_interface     ;7


driver_name db "mTCP NetDrive", 0


soft_int_dispatcher:

  jmp short soft_int_dispatcher_start
  nop
  db               "PKT DRVR", 0

  soft_int_dispatcher_start:

  push  ax
  push  bx
  push  cx
  push  dx
  push  si
  push  di
  push  bp
  push  ds
  push  es

  ; Use BP to access the caller's register values.
  mov   bp, sp

  ; Re-establish our data segment
  mov   ax, cs
  mov   ds, ax

  ; Assume things will work
  and   p_FLAGS[bp], not CARRY_BIT

  ; The function number is in AH.  Isolate it in AL and use it with the
  ; function table to make the call.  If the function number is above what
  ; we support set it to f_not_implemented.

  xor   ax, ax
  mov   al, p_AH[bp]
  cmp   al, call_reset                   ; f_reset_interface
  jbe   soft_int_dispatcher_make_call

  mov   al, 0                            ; f_not_implemented

  soft_int_dispatcher_make_call:
  add   ax, ax
  mov   di, OFFSET function_table
  add   di, ax
  call  word ptr[di]
  jnc   soft_int_dispatcher_exit

  ; If the function returned an error stuff the error code in the saved regs
  ; and set the carry flag.
  ;
  mov   p_DH[bp], dh
  or    p_FLAGS[bp], CARRY_BIT

  soft_int_dispatcher_exit:

  pop   es
  pop   ds
  pop   bp
  pop   di
  pop   si
  pop   dx
  pop   cx
  pop   bx
  pop   ax

  iret


f_not_implemented proc near
  return_with_error err_BAD_COMMAND
f_not_implemented endp


verify_handle proc near

  mov   bx, p_BX[bp]                     ;get the handle they gave us
  cmp   bx, OFFSET handles
  jb    verify_handle_bad                ;no - must be bad.
  cmp   bx, OFFSET end_handles
  jae   verify_handle_bad                ;no - must be bad.
  cmp   [bx].handle_in_use, 1            ;if it's not in use, it's bad.
  jne   verify_handle_bad
  ret

  verify_handle_bad:
  mov   dh, ERR_BAD_HANDLE
  add   sp, 2                            ;pop off our return address.
  stc
  ret

verify_handle endp


f_driver_info proc near

  ; Do not verify the handle - it doesn't make sense and it's not required now.

  ; Enforce that AL was set correctly, but it doesn't have an associated
  ; return code so just set the carry flag if it is incorrect.  (DH would
  ; normally be modified; do not do that in this case.)

  cmp   p_AL[bp], 0xff
  je    f_driver_info_1
  return_with_error dh

  f_driver_info_1:
  mov   p_BX[bp], 1                      ; Version
  mov   p_CH[bp], 1                      ; Class (Ethernet)
  mov   p_CL[bp], 0x0                    ; Interface number
  mov   p_DX[bp], 0xff                   ; Type (doesn't matter)
  mov   p_DS[bp], cs                     ; Segment and offset to driver_name
  mov   p_SI[bp], OFFSET driver_name
  mov   p_AL[bp], 0x1                    ; Basic functions only
  ret

f_driver_info endp


f_access_type proc near

  ; Class has to match.  We are doing DIX for now and maybe 802.3 later.
  cmp   p_AL[bp], 1
  jne   f_access_type_no_class

  ; Type must match the generic type; there was no type definition for DaynaPORT
  cmp   p_BX[bp], 0xffff
  jne   f_access_type_no_type

  ; Interface number must always be 0 (the first interface)
  cmp   p_DL[bp], 0
  jne   f_access_type_no_number


  ; Find an open handle.
  ;
  ; If they said "any packet" (typelen - 0) then always use the last slot
  ; in the handle table for that.  That makes it serve as a catch-all for
  ; any EtherType not explicitly claimed.
  ;
  ; For any other EtherType the entire table has to be searched to ensure
  ; it has not already been claimed.

  mov   handle_found, 0

  cmp   p_CX[bp], 0
  je    f_access_type_start_searching_at_end

  ; DX will have the requested EtherType in it and we will search the entire table.
  mov   es, p_DS[bp]
  mov   di, p_SI[bp]
  mov   dx, es:[di]

  mov   bx, OFFSET handles
  jmp   f_access_type_handle_search_top

  f_access_type_start_searching_at_end:
  ; Ethertype is "0" and we only search the last slot.
  mov   dx, 0
  mov   bx, OFFSET end_handles - (size handle_rec)

  f_access_type_handle_search_top:

    cmp   [bx].handle_in_use, 0          ; Not in use; note that we can use this.
    je    f_access_type_open_handle

    mov   ax, [bx].handle_type           ; Slot is used; if same EtherType we are done.
    cmp   ax, dx
    je    f_access_type_type_in_use

    jmp   f_access_type_move_to_next_slot

    f_access_type_open_handle:
    ; Only mark the open handle if we have not found one already.
    cmp   handle_found, 0
    jne   f_access_type_move_to_next_slot

    mov   handle_found, bx

    f_access_type_move_to_next_slot:
    add   bx, size handle_rec
    cmp   bx, OFFSET end_handles
    jne   f_access_type_handle_search_top


  ; If you made it here the EtherType was not in use.  (And if it was the
  ; catch-all type, that is not in use either.)

  cmp   handle_found, 0
  je    f_access_type_no_space

  mov   bx, handle_found
  mov   [bx].handle_in_use, 1
  mov   [bx].handle_type, dx
  mov   ax, p_DI[bp]
  mov   word ptr [bx].receiver, ax
  mov   ax, p_ES[bp]
  mov   word ptr [bx].receiver+2, ax
  inc   handles_in_use

  mov   p_AX[bp], bx
  ret


  f_access_type_no_class:
  return_with_error ERR_NO_CLASS
  f_access_type_no_type:
  return_with_error ERR_NO_TYPE
  f_access_type_no_number:
  return_with_error ERR_NO_NUMBER
  f_access_type_no_space:
  return_with_error ERR_NO_SPACE
  f_access_type_type_in_use:
  return_with_error ERR_TYPE_IN_USE

f_access_type endp


f_release_type proc near
  call verify_handle                     ; Does not return on failure.
  mov   [bx].handle_in_use, 0            ; Mark as not in use.
  dec   handles_in_use
  ret
f_release_type endp


f_send_pkt proc near

  push  ds

  ; Basically just pass through what they gave us.
  mov   ah, call_SEND
  mov   cx, p_CX[bp]
  mov   si, p_SI[bp]
  mov   ds, p_DS[bp]

  ; On return if there was an error DH will have an error code and the carry
  ; flag will be set.
  call  doPacketInterrupt

  pop   ds


  ret
f_send_pkt endp


f_terminate proc near

  ; Terminate is weird in this context, as we are not going to unload or
  ; unhook anything.  We just mark their handle as released and if there
  ; are no more handles we claim we are done.

  call verify_handle                     ; Does not return on failure.

  ; Mark this handle as not in use and decrease the number of handles in use.
  ; If no more handles are in use we can continue and terminate.

  mov   [bx].handle_in_use, 0
  dec   handles_in_use
  cmp   handles_in_use, 0
  jne   f_terminate_cant_terminate

  ret

  f_terminate_cant_terminate:
  return_with_error ERR_CANT_TERMINATE

f_terminate endp


f_get_address proc near

  ; This happens rarely so don't optimize it.
  ;
  ; Save their handle (in bx) in case they need it; alter it to the real
  ; handle being used, and then call the packet driver.

  mov  ah, call_GET_ADDRESS
  mov  bx, shared_data.net_pkt_drv_hndl
  mov  es, p_ES[bp]
  mov  di, p_DI[bp]
  mov  dx, p_CX[bp]

  ; On return if there was an error DH will have an error code and the carry
  ; flag will be set.
  call doPacketInterrupt

  ret
f_get_address endp


f_reset_interface proc near

  call  verify_handle                     ; Does not return on failure.

  cmp   handles_in_use, 1
  ja    f_reset_interface_cant

  ret

  f_reset_interface_cant:
  ; Not allowed to pull the rug if other handles are active.
  return_with_error err_CANT_RESET

f_reset_interface endp




; ============================================================================
;

; After the initialization routine runs we are going to reuse the data area
; for the per-unit connection data.  This allows us to use exactly the amount
; of the storage called for by the number of units.

even
units_storage label unit_data


drive_units_opt    db          1         ; Assume 1 unit will be installed
ten                db         10         ; Used to divide by 10
cursor_off         dw          ?         ; current offset of our config.sys line
cursor_seg         dw          ?         ; segment of our config.sys line


printMsg macro mesg:REQ
  mov dx, OFFSET mesg
  mov ah, 9
  int 0x21
endm

printErrAndExit macro mesg:REQ
  mov dx, OFFSET mesg
  mov ah, 9
  int 0x21
  jmp   initial_error_path
endm


initial proc near

  ; Set some addresses that the NETDRIVE.EXE program will use.
  ;
  ; Everything else in shared_data/net_data is initialized to zeros.

  mov   shared_data.net_segment, cs
  mov   shared_data.net_receiver_off, OFFSET receivePacket
  mov   shared_data.net_shim_off, OFFSET soft_int_dispatcher
  mov   shared_data.net_int_inst_off, OFFSET doPacketInterrupt

  ifdef CHKSUM_TESTING
  mov   word ptr shared_data.test_IP, OFFSET testIpChksum
  mov   word ptr shared_data.test_IP+2, cs
  mov   word ptr shared_data.test_UDP, OFFSET testUdpChksum
  mov   word ptr shared_data.test_UDP+2, cs
  endif

  printMsg Hello


  ; scanswitch setup
  ;
  ; The request header has a pointer to our line in config.sys after "device='.
  ; Place that address in cursor_off and cursor_seg, where scanswitch can load it.
  ; scanswitch will advance it and use cursor_off and cursor_seg to remember where
  ; it left off.

  mov   ax, es:[bx].rh0_bpb_array_off
  mov   cursor_off, ax
  mov   ax, es:[bx].rh0_bpb_array_off+2
  mov   cursor_seg, ax

  cld

  initial_scanswitches_top:
  push  ds                       ; scanswitch alters ds
  call  scanswitch
  pop   ds                       ; restore ds

  cmp   cl, 0
  jz    initial_no_more_switches

  cmp   cl, 255
  jz    initial_switch_format_error

  cmp   cl, 'd'
  jnz   initial_unknown_switch


  ; The -d switch is only legal between 1 and 4 drives.  Reject other values.
  cmp   bx, 1
  jb    initial_bad_drive_count
  cmp   bx, Max_Units
  ja    initial_bad_drive_count

  mov   drive_units_opt, bl
  jmp   initial_scanswitches_top


  initial_bad_drive_count:
  printErrAndExit BadDriveCnt

  initial_unknown_switch:
  printErrAndExit UnknownSwitch

  initial_switch_format_error:
  printErrAndExit BadSwitchFormat


  initial_no_more_switches:

  mov   ah, 0x30                         ; Get DOS version
  int   0x21
  cmp   al, 2
  jnz   initial_above_dos_2              ; Skip if better than DOS 2

  printMsg Hello2_DOS2
  jmp   initial_num_drives

  initial_above_dos_2:

  ; reload es:bx to get the drive number from the RH header
  mov   ax, cs:rh_seg
  mov   es, ax
  mov   bx, cs:rh_off

  mov   al, es:[bx].rh0_first_drive       ; Drive number from RH header
  add   al, 'A'                           ; Make it ASCII
  mov   shared_data.net_first_letter, al  ; Save it for future reference.
  mov   DriveLetter, al
  printMsg Hello2

  initial_num_drives: 

  xor   ax, ax
  mov   al, drive_units_opt
  div   ten
  add   al, 48
  add   ah, 48
  cmp   al, 48
  jnz   initial_double_digits

  ; Just one digit to display
  mov   UnitsSupported2, ah
  jmp   initial_print_number

  initial_double_digits:
  mov   UnitsSupported2, al
  mov   UnitsSupported2+1, ah

  initial_print_number:
  printMsg UnitsSupported1

  initial_timer_setup:

  ; Hook timer interrupt so we can have a countdown timer.
  ; We should be able to use the BIOS tick interrupt for this but the
  ; 3Com PCI packet driver hangs if you do, so hook IRQ 0 instead.

  push  ds
  xor   ax, ax
  mov   ds, ax
  mov   ax, ds:[8h*4]
  mov   dx, ds:[8h*4+2]
  pushf
  cli
  mov   ds:[8h*4], OFFSET timerInt
  mov   ds:[8h*4+2], cs
  mov   word ptr cs:[timerOrigInt], ax
  mov   word ptr cs:[timerOrigInt+2], dx
  sti
  popf
  pop ds


  ; Set the base pointer for the unit specific storage to make it easy to find.
  mov shared_data.net_units_start, OFFSET units_storage


  ; DOS 2.x claims to update the header with the number of units based on the
  ; return code and later versions of DOS actually do it.  Do it unconditionally
  ; here so DOS 2.x is consistent and we can use the value from the command line
  ; utility.

  mov    al, drive_units_opt
  mov    cs:unit_count, al


  ; Setup to wipe out the unit specific data to zeros.  The actual wiping
  ; will be done on return, as it steps on the memory where this code is
  ; currently sitting.

  xor    dx, dx                          ; Get number of units in dx
  mov    dl, al
  mov    ax, size unit_data              ; Size of unit structure
  mul    dx
  mov    dx, ax                          ; Save bytes in dx for later
  shr    ax, 1                           ; Divide by 2 to get words
  mov    cx, ax                          ; Setup count for the rep stosw loop


  ; DX has the number of bytes for the unit storage.  Add an offset to the
  ; unit storage, which then makes it the starting location for the next driver.
  add    dx, OFFSET units_storage

  ; Record where our incoming and outgoing packet buffers are going to be.
  mov    incoming_buf_p, dx
  add    dx, ETH_FRAME_SIZE
  mov    outgoing_buf_p, dx
  add    dx, ETH_FRAME_SIZE

  ; Restore pointer to request header in ES:BX
  mov    ax, cs:rh_seg
  mov    es, ax
  mov    bx, cs:rh_off

  ; Return number of supported units.  Also provde a pointer to the BPB array
  ; for the initial ram disks (one for each unit.)

  mov    al, cs:unit_count
  mov    es:[bx].rh0_units, al
  mov    word ptr es:[bx].rh0_bpb_array_off, OFFSET RamDiskBPBArray
  mov    word ptr es:[bx].rh0_bpb_array_seg, cs


  ; Set the address to load the next driver at.  After our unit storage.
  mov    es:[bx].rh0_brk_off, dx
  mov    es:[bx].rh0_brk_seg, cs


  ; Setup to clear the bytes on return; CX still has the words to clear.

  mov    ax, cs                          ; es:di points to the unit storage
  mov    es, ax
  mov    di, OFFSET units_storage 
  xor    ax, ax

  ret



  initial_error_path:

  ; Restore pointer to request header in ES:BX
  mov    ax, cs:rh_seg
  mov    es, ax
  mov    bx, cs:rh_off

  ; Set units to 0, set the error flag, and set the break location to the
  ; very start (the attribute word) so that DOS discards the storage and
  ; installs nothing.

  mov    es:[bx].rh0_units, 0
  mov    es:[bx].rh_status, 0x8000
  mov    ax, OFFSET next_dev
  mov    es:[bx].rh0_brk_off, ax
  mov    es:[bx].rh0_brk_seg, cs

  ; Copy no bytes on return
  mov    cx, 0

  ret

initial endp




; Return values: cl is the switch letter (lower case) and bx is the value.
; cl == 0 means no more switches and cl == 255 is a format error

scanswitch proc near

  ; Clear return codes
  xor bx, bx
  mov cx, bx

  ; Reload the current position into ds:si
  mov ax, cs:cursor_seg
  mov ds, ax
  mov si, cs:cursor_off

  ; Look for our switch character ('-') or the end of the line.
  scanswitch1:
  lodsb
  cmp   al, 13
  jz    scanswitch_done
  cmp   al, 10
  jz    scanswitch_done
  cmp   al, '-'
  jnz   scanswitch1

  lodsb
  or    al, 0x20
  cmp   al, 'a'
  jb    scanswitch_badswitch
  cmp   al, 'z'
  ja    scanswitch_badswitch
  mov   cl, al
  lodsb
  cmp   al, ':'
  jnz   scanswitch_badswitch

  lodsb
  cmp   al, '0'
  jb    scanswitch_badswitch
  cmp   al, '9'
  ja    scanswitch_badswitch

  sub   al, '0'
  cbw
  mov   bx, ax

  getnum:
  lodsb
  cmp   al, ' '
  jz    scanswitch_done
  cmp   al, 13
  jz    scanswitch_done
  cmp   al, 10
  jz    scanswitch_done
  cmp   al, '0'
  jb    scanswitch_badswitch
  cmp   al, '9'
  ja    scanswitch_badswitch

  sub   al, '0'
  cbw
  xchg  ax, bx
  mov   dx, 10
  mul   dx
  add   bx, ax
  jmp   getnum


  scanswitch_badswitch:
  mov cl, 255
  ret

  
  scanswitch_done:

  mov cs:cursor_off, si
  mov cs:cursor_seg, ds

  ret

scanswitch endp



Hello           db    'mTCP NetDrive (Nov 10 2023) by M Brutman (C) 2023-2026 (www.brutman.com/mTCP)',13,10,'$'
Hello2_DOS2     db    '  First network drive is (unknown - DOS 2.x detected), ','$'
Hello2          db    '  First network drive is '
DriveLetter     db    'X:, ','$'
UnitsSupported1 db    'Number of drives: '
UnitsSupported2 db    '  ',13,10,'$'

BadSwitchFormat db    '  Error: Bad switch format, not loading',13,10,'$'
BadDriveCnt     db    '  Error: Bad number of drives on -d switch, not loading',13,10,'$'
UnknownSwitch   db    '  Error: Invalid switch specified, not loading',13,10,'$'


net    endp
cseg   ends
       end begin
