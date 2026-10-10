; mTCP NetDrive (SHIM.ASM)
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
; Description: Definitions for the pass-through packet driver.




return_with_error macro errcode:REQ
  mov   dh, errcode
  stc
  ret
endm




; Necessary packet driver constants from http://crynwr.com/packet_driver.html.

; Function numbers that we support.

call_DRIVER_INFO    equ 1
call_ACCESS_TYPE    equ 2
call_RELEASE_TYPE   equ 3
call_SEND           equ 4
call_TERMINATE      equ 5
call_GET_ADDRESS    equ 6
call_RESET          equ 7


; Errors

err_BAD_HANDLE      equ 1
err_NO_CLASS        equ 2
err_NO_TYPE         equ 3
err_NO_NUMBER       equ 4
err_BAD_TYPE        equ 5
err_NO_MULTICAST    equ 6
err_CANT_TERMINATE  equ 7
err_BAD_MODE        equ 8
err_NO_SPACE        equ 9
err_TYPE_IN_USE     equ 10
err_BAD_COMMAND     equ 11
err_CANT_SEND       equ 12
err_CANT_SET        equ 13
err_BAD_ADDRESS     equ 14
err_CANT_RESET      equ 15




; Packet handle management
;

MAX_HANDLES        equ 10

handle_rec struc
  handle_in_use     db 0                     ; This handle is in use.
                    db ?
  handle_type       dw 0                     ; EtherType for the handle.
  receiver          dd 0                     ; User receiver call entry point.
handle_rec ends



; Registers saved by soft_int_dispatcher.  Also includes the IP, CS and FLAGS
; registers that were pushed by the interrupt.  On entry these are the user
; parameters and on exit these are the return values.

user_parms_words struc
  p_ES     dw  ?
  p_DS     dw  ?
  p_BP     dw  ?
  p_DI     dw  ?
  p_SI     dw  ?
  p_DX     dw  ?
  p_CX     dw  ?
  p_BX     dw  ?
  p_AX     dw  ?
  p_IP     dw  ?
  p_CS     dw  ?
  p_FLAGS  dw  ?
user_parms_words ends


; The same as above, but with the half-word registers broken out.

user_parms_bytes struc
           dw  ?        ; ES
           dw  ?        ; DS
           dw  ?        ; BP
           dw  ?        ; DI
           dw  ?        ; SI
  p_DL     db  ?
  p_DH     db  ?
  p_CL     db  ?
  p_CH     db  ?
  p_BL     db  ?
  p_BH     db  ?
  p_AL     db  ?
  p_AH     db  ?
           dw  ?        ; IP
           dw  ?        ; CS
           dw  ?        ; FLAGS
user_parms_bytes ends


CARRY_BIT equ 0x0001

