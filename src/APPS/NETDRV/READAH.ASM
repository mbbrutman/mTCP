; Copyright (C) 2025-2026 Michael B. Brutman (mbbrutman@gmail.com)
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
; Description: Variables used for the read-ahead feature.  And lots
; of commentary.




; ReadAhead logic
;
; Each time DOS calls the device driver to do a read it tells the device
; driver the number of blocks that it needs.  The device driver breaks
; that into smaller chunks (1 or 2 blocks to fit in a non-fragmented
; UDP packet) and loops until the read is done.
;
; The client has to send the first read request to get things started.
; Every time it sends a read request it also tells the server the total
; remaining outstanding blocks that are to be read (including the ones
; in the current read request) and the amount of buffer space is has
; available.  This allows the server to satisfy the read request (which
; it must do) and then optionally send read-ahead blocks in addition,
; up to the number of outstanding blocks or the size of the read-ahead
; area, whichever is less.
;
; There is an important nuance here - this is not a cache.  The user
; is providing the buffer space and we can only store blocks that
; belong to the read that the user is executing.  (A general purpose
; cache would allow us to cache any blocks regardless of what the
; user is doing.)
;
; Read-ahead packets are asynchronous in the sense that the client is
; not spinning waiting for them, but they are triggered by an open
; read from DOS to the device driver.  So they have to be able to be
; written to the user buffer that the DOS caller as been provided.
; Otherwise, they need to be discarded because there is no place
; to put them.  It would be possible to have a separate cache for those
; blocks if we thought that would be useful, but that requires storage.
;
; If the server sends the optional blocks they are sent first, allowing
; the client to read them and start filling the user buffer.  Then
; the response to the actual read request is sent.  The client is spinning
; waiting for that so as soon as that happens it will start preparing to
; send requests for the next blocks, see see they have already been
; stored, and skip them.  (Hopefully.)
;
;
; Error handling:
;
; If a read command times out, it will be resent as it originally was.
; That might cause the sever to resend all of the read-ahead blocks too,
; which is probably unnecessary.  So the server should not bother doing
; that; read-ahead will resume soon enough anyway.
;
; If a read-ahead block gets dropped, then it is just not recorded as
; having arrived.  The device driver will get to the hole in the user
; buffer and send a read request for that data.  It won't bother to
; check to see if the next block is in the cache or not, but that's
; an optimization we can add.  (Probably not worth doing.)
; 
;
; Data integrity
;
; As this is UDP and we support multiple connected clients there are
; several hazards to be aware of:
;
; * Multiple drive letter connections; read-ahead data is only valid for
;   one drive letter.
;
; * Writes - when read-ahead packets were going to a separate cache we
;   had to invalidate that cache when a write started.  Now that
;   read-ahead packets go straight to the open read user buffer this is
;   not a concern; if there is no open read then any read-ahead packets
;   get dropped.
;
; * UDP can duplicate packets or send things late.  We don't want old
;   read-ahead data from before a write operation to show up during or
;   after a write and get put in the cache.
;
; To get around these multiple hazards we do the following:
;
; * The read-ahead cache is always invalided each time a new read command
;   is issued by DOS.
;
; * Read-ahead data is only used if the sequence number in the read-ahead
;   packet is at least as large as the sequence number when DOS issued
;   the command.  (This ensures that it is the current user read command
;   with the same user space buffer.
;
;
; Remember, the OS can file OS level buffering of data.  We don't need to
; do that here.


RA_MAX_BLOCK       equ    129

                   db      'RD_AHEAD'

; Bitmap to track blocks received by read-ahead.  Bit 0 and 1 (the bits for
; the first blocks in a reqd request) will never get used, so add one extra
; byte and use two more bits to compensate for that.  (Actually add two bytes
; to maintain even alignment.)
;
ra_slot_valid      db     18 dup (0)         ; Bitmap of blocks received by read-ahead.

ra_seq_start       dw      0                 ; The minimum sequence number to allow.
ra_lba_start       dd      0                 ; Starting sector of the last read from DOS.
ra_lba_count       dw      0                 ; Full count of sectors to read.
ra_buf_off         dw      0                 ; User buffer start offset.
ra_buf_seg         dw      0                 ; User buffer start segment.

; Used on the receive path; indicates which block in the read-ahead packet (first
; or second) we are working with.
;
ra_receive_index   dw      0


