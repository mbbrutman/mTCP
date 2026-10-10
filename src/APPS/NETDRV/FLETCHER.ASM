; mTCP NetDrive (FLETCHER.ASM)
; Copyright (C) 2026-2026 Michael B. Brutman (mbbrutman@gmail.com)
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
; Description: The Fletcher-32 checksum, as described by Wikipedia but very
; heavily optimized for our use case.
; 
; https://en.wikipedia.org/wiki/Fletcher%27s_checksum


; fck32
;
;
; Inputs:
;   DS:SI is the user buffer address.
;   CX is the length in bytes (not preserved)
;
; Output:
;   AX (low 16 bits) and DX (high 16 bits)
;
; Warning: Lots of registers used, non preserved ...


fck32_input_len dw ?

fck32 proc

  mov    cs:fck32_input_len, cx

  ; Clear local counters
  xor   bx, bx               ; WORD PTR c0
  xor   di, di               ; WORD PTR c0+2
  xor   dx, dx               ; WORD PTR c1
  xor   bp, bp               ; WORD PTR c1+2

  cld

  fck32_outer_loop:

  ; 720 bytes will be processed by the inner loop.  It is doing a word at
  ; a time so it is only 360 iterations of the loop.
  mov   cx, cs:fck32_input_len
  cmp   cx, 720
  jbe   fck32_size_set
  mov   cx, 720

  fck32_size_set:
  sub   cs:fck32_input_len, cx           ; Subtract the number of bytes from the total
  shr   cx, 1                            ; Divide this group length by 2 beause we are doing words.

  shr   cx, 1                            ; Loop unrolling - we are doing 8 bytes per iteration.
  shr   cx, 1                            ; So input lengths have to be multiples of 8.

  fck32_inner_loop:
  lodsw
  add   bx, ax
  adc   di, 0
  add   dx, bx
  adc   bp, di
  lodsw
  add   bx, ax
  adc   di, 0
  add   dx, bx
  adc   bp, di
  lodsw
  add   bx, ax
  adc   di, 0
  add   dx, bx
  adc   bp, di
  lodsw
  add   bx, ax
  adc   di, 0
  add   dx, bx
  adc   bp, di
  loop  fck32_inner_loop

  ; Fast modulo 65536 on c0
  add   bx, di
  adc   bx, 0
  cmp   bx, 0xffff
  jne   fck32_mod1_1
  xor   bx, bx
  fck32_mod1_1:
  xor   di, di

  ; Fast modulo 65536 on c1
  add   dx, bp
  adc   dx, 0
  cmp   dx, 0xffff
  jne   fck32_mod1_2
  xor   dx, dx
  fck32_mod1_2:
  xor   bp, bp

  cmp   cs:fck32_input_len, 0
  ja    fck32_outer_loop

  ; Result in AX (low 16 bits) and DX (high 16 bits)
  mov   ax, bx

  ret

fck32 endp
