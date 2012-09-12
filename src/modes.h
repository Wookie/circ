/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with main.c; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor Boston, MA 02110-1301,  USA
 */

#ifndef __IRC_MODES_H__
#define __IRC_MODES_H__

#include <stdint.h>

typedef enum irc_umode_e
{
	/*  mode  */	/* parameter, if any */
	IRC_UMODE_a,
	IRC_UMODE_b,
	IRC_UMODE_c,
	IRC_UMODE_d,	/* prefix character to receive chan msg */
	IRC_UMODE_f,
	IRC_UMODE_g,
	IRC_UMODE_h,	/* unsigned 16-bit int denotes 'rank' */
	IRC_UMODE_i,
	IRC_UMODE_k,
	IRC_UMODE_l,
	IRC_UMODE_m,
	IRC_UMODE_n,
	IRC_UMODE_o,
	IRC_UMODE_p,
	IRC_UMODE_q,
	IRC_UMODE_r,
	IRC_UMODE_s,	/* list of letters corresponding to server notices to receive */
	IRC_UMODE_t,
	IRC_UMODE_u,
	IRC_UMODE_v,
	IRC_UMODE_w,
	IRC_UMODE_x,
	IRC_UMODE_y,
	IRC_UMODE_z,

	IRC_UMODE_A,
	IRC_UMODE_B,
	IRC_UMODE_C,
	IRC_UMODE_G,
	IRC_UMODE_H,
	IRC_UMODE_I,
	IRC_UMODE_N,
	IRC_UMODE_O,
	IRC_UMODE_R,
	IRC_UMODE_S,
	IRC_UMODE_T,
	IRC_UMODE_V,
	IRC_UMODE_W,

	IRC_UMODE_LAST,
	IRC_UMODE_FIRST = IRC_UMODE_a,
	IRC_UMODE_COUNT = IRC_UMODE_LAST - IRC_UMODE_FIRST

} irc_umode_t;

typedef enum irc_cmode_e
{
	/*  mode  */	/* parameter, if any */
	IRC_CMODE_a,	/* nick that can't be kicked/deopped */
	IRC_CMODE_b,	/* <n!u@h> banned nick mask */
	IRC_CMODE_c,
	IRC_CMODE_d,	/* real name to ban */
	IRC_CMODE_e,	/* <n!u@h> banned nick exception mask */
	IRC_CMODE_f,	/* <lines>:<second> lines per second flood limit */
	IRC_CMODE_h,	/* nick to grant half-op status */
	IRC_CMODE_i,	/* <n!u@h> nick mask to allow past invite only restriction */
	IRC_CMODE_j,	/* n:t n users may join in each period of t seconds */
	IRC_CMODE_k,	/* channel password that must be given with JOIN */
	IRC_CMODE_l,	/* <int> upper limit on number of channel members */
	IRC_CMODE_m,
	IRC_CMODE_n,
	IRC_CMODE_o,	/* nick to grant chan op status */
	IRC_CMODE_p,
	IRC_CMODE_q,	/* nick to grant channel owner status */
	IRC_CMODE_r,
	IRC_CMODE_s,
	IRC_CMODE_t,
	IRC_CMODE_u,
	IRC_CMODE_v,	/* nick to give voice to in moderated channels (+m) */
	IRC_CMODE_z,
	IRC_CMODE_BANG,	/* nick to mark as a channel service */

	IRC_CMODE_A,
	IRC_CMODE_C,
	IRC_CMODE_D,
	IRC_CMODE_G,
	IRC_CMODE_H,
	IRC_CMODE_I,
	IRC_CMODE_J,	/* <frequency>,<limit> users may join once per every 'frequency' seconds with an initial burst and limit of 'limit' users */
	IRC_CMODE_K,
	IRC_CMODE_L,
	IRC_CMODE_M,
	IRC_CMODE_N,
	IRC_CMODE_O,	/* nick to grant channel owner status */
	IRC_CMODE_Q,
	IRC_CMODE_R,	/* <n!u@h> mask to serve as hint for re-op when chan is op-less */
	IRC_CMODE_S,
	IRC_CMODE_V,

	IRC_CMODE_LAST,
	IRC_CMODE_FIRST = IRC_CMODE_a,
	IRC_CMODE_COUNT = IRC_CMODE_LAST - IRC_CMODE_FIRST

} irc_cmode_t;

typedef enum irc_smode_e
{
	/*  mode  */		/* parameter, if any */
	IRC_SMODE_a,
	IRC_SMODE_h,
	IRC_SMODE_l,
	IRC_SMODE_n,
	IRC_SMODE_s,

	IRC_SMODE_A,
	IRC_SMODE_D,
	IRC_SMODE_F,
	IRC_SMODE_H,
	IRC_SMODE_L,	/* language code */
	IRC_SMODE_M,
	IRC_SMODE_T,

	IRC_SMODE_LAST,
	IRC_SMODE_FIRST = IRC_SMODE_a,
	IRC_SMODE_COUNT = IRC_SMODE_LAST - IRC_SMODE_FIRST

} irc_smode_t;

#define IS_UMODE(x) ( \
		((x >= 'a') && (x <= 'A') && (x >= 'z') && (x <= 'Z')) && \
		(x != 'e') && \
		(x != 'j') && \
		(x != 'D') && \
		(x != 'E') && \
		(x != 'F') && \
		(x != 'J') && \
		(x != 'K') && \
		(x != 'L') && \
		(x != 'M') && \
		(x != 'P') && \
		(x != 'Q') && \
		(x != 'U') && \
		(x != 'X') && \
		(x != 'Y') && \
		(x != 'Z') )

#define IS_CMODE(x) ( \
		(((x >= 'a') && (x <= 'A') && (x >= 'z') && (x <= 'Z')) || (x == '!')) && \
		(x != 'g') && \
		(x != 'w') && \
		(x != 'x') && \
		(x != 'y') && \
		(x != 'B') && \
		(x != 'E') && \
		(x != 'F') && \
		(x != 'P') && \
		(x != 'T') && \
		(x != 'U') && \
		(x != 'W') && \
		(x != 'X') && \
		(x != 'Y') && \
		(x != 'Z') )

#define IS_SMODE(x) ( \
		(x == 'a') || \
		(x == 'h') || \
		(x == 'l') || \
		(x == 'n') || \
		(x == 's') || \
		(x == 'A') || \
		(x == 'D') || \
		(x == 'F') || \
		(x == 'H') || \
		(x == 'L') || \
		(x == 'M') || \
		(x == 'T'))

irc_umode_t a_to_umode( int8_t const c );
irc_cmode_t a_to_cmode( int8_t const c );
irc_smode_t a_to_smode( int8_t const c );

#endif//__IRC_MODES_H__

