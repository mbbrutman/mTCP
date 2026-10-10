; mTCP NetDrive (RH.ASM)
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
; Description: DOS Request Header data structures



; Data structures
;
; Request Header (common part)
;
; Always 13 bytes long no matter what version of DOS

rh                 struc                 ; DOS request header
rh_len             db          ?         ; Length of packet
rh_unit            db          ?         ; Unit code (block devices)
rh_cmd             db          ?         ; Command
rh_status          dw          ?         ; Return code?
rh_res1            dd          ?         ; Reserved, 32 bits
rh_res2            dd          ?         ; Reserved, 32 bits
rh                 ends


; Initialization (Cmd 0)

rh0                struc
rh0_rh             db size rh dup (?)
rh0_units          db          ?         ; Output: number of units block devices only
rh0_brk_off        dw          ?         ; Output: Offset for break
rh0_brk_seg        dw          ?         ; Output: Segment for break
rh0_bpb_array_off  dw          ?         ; Input: parms, Output: BPB Array offset
rh0_bpb_array_seg  dw          ?         ; Input: parms, Output: BPB Array segment
rh0_first_drive    db          ?         ; Input: first drive number
rh0_err_msg_flag   dw          ?         ; Dos 4+ only? Not going to use this.
rh0                ends


; Media Check (Cmd 1)

rh_media_chk       struc
rh_media_rh        db size rh dup (?)
rh_media_media     db          ?         ; Media descriptor
rh_media_return    db          ?         ; Output: media status (0, 1, or 0xff)
rh_media_volid     dd          ?         ; Only needed if removable media dh attr set.
rh_media_chk       ends


; Build BPB (Cmd 2)

rh_get_bpb         struc
rh_get_bpb_rh      db size rh dup (?)
rh_get_bpb_media   db          ?         ; Media descriptor
rh_get_bpb_dta_off dw          ?         ; Data Transfer Area offset (not used)
rh_get_bpb_dta_seg dw          ?         ; Data Transfer Area segment (not used)
rh_get_bpb_bpb_off dw          ?         ; Return value: BPB offset
rh_get_bpb_bpb_seg dw          ?         ; Return value: BPB segment
rh_get_bpb         ends


; IOCTL Read (Cmd 3) and Write (Cmd 12)

rh_ioctl           struc
rh_ioctl_rh        db size rh dup (?)
rh_ioctl_media     db          ?         ; Media descriptor (block devices only)
rh_ioctl_buf_off   dw          ?         ; Buffer offset
rh_ioctl_buf_seg   dw          ?         ; Buffer segment
rh_ioctl_count     dw          ?         ; Byte or sector count
rh_ioctl_start     dw          ?         ; Start sector number
rh_ioctl           ends


; Input/Read (Cmd 4), Output/Write (Cmd 8), and Output/Write Verify (Cmd 9)

rh_input           struc
rh_input_rh        db size rh dup (?)
rh_input_media     db          ?         ; Media descriptor (block devices only)
rh_input_buf_off   dw          ?         ; Transfer address offset
rh_input_buf_seg   dw          ?         ; Transfer address segment
rh_input_count     dw          ?         ; byte (char) or sector (block) count
rh_input_start     dw          ?         ; starting sector (block)
rh_input_volIdPtr  dd          ?         ; DOS 3.0+ pointer to vol ID if error 0x0F returned
rh_input_hugeStart dd          ?         ; DOS 4.0+ starting sector count (32 bit mode)
rh_input           ends


; Notes on the input RH length.
;
; DOS 2.x  the RH length is 22 bytes long.  rh_input_start is the last field.
; DOS 3.x  the RH length is 22 bytes long.  rh_input_volIdPtr is only used on output?
; DOS 4.x+ the RH length is 30 bytes long.  rh_input_hugeStart is the last field.
;
; Cpq DOS 3.31 the RH length is 24 bytes long. rh_input_start is interpreted as a 32 bit field.
;
; For DOS 3.x I don't know why rh_input_volIdPtr is not part of the request header length.
; Cpq DOS 3.31 also doesn't include it in it's RH length, possibly because it is output
; only?  We don't ever set the "Invalid disk change" return code so we never have to
; supply that field.


