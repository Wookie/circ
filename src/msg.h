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
 
#ifndef __IRC_MSG_H__
#define __IRC_MSG_H__

#include <netinet/in.h>
#include <cutil/list.h>
#include <cutil/socket.h>

#define IRC_MSG_SIZE (512)
#define IRC_NUM_PARAMS (15)
#define IRC_NICKNAME_MAX (9)

typedef enum irc_host_type_e
{
	NO_HOST = 0,
	V4_HOSTADDR = 1,
	V6_HOSTADDR = 2,
	HOSTNAME = 3,

	LAST_MSG_HOST,
	FIRST_MSG_HOST = NO_HOST,
	NUM_MSG_HOST = LAST_MSG_HOST - FIRST_MSG_HOST

} irc_host_type_t;

#define IS_VALID_MSG_HOST(x)  ((x >= FIRST_MSG_HOST) && (x < LAST_MSG_HOST))

typedef enum irc_prefix_type_e
{
	CONN_PREFIX = 0,				/* no prefix in message, origin from connection */
	SERVERNAME_PREFIX = 1,			/* prefix is server name */
	NUH_PREFIX = 2,					/* prefix is name [ [ '!' user] '@' host ] */

	LAST_PREFIX,
	FIRST_PREFIX = CONN_PREFIX,
	NUM_PREFIX = LAST_PREFIX - FIRST_PREFIX

} irc_prefix_type_t;

#define IS_VALID_PREFIX(x) ((x >= FIRST_PREFIX) && (x < LAST_PREFIX))

typedef struct irc_str_ref_s        /* string reference */
{
    struct iovec       v;           /* pointer to mem and len of data */
    int_t              dyn;         /* is it dynamically allocated? */

} irc_str_ref_t;

#define STR_PTR(s) ((uint8_t*)((struct iovec*)&s)->iov_base)
#define STR_PTR_P(p) ((uint8_t*)((struct iovec*)p)->iov_base)
#define STR_PTR_SET(s, v) (((struct iovec*)&s)->iov_base = v)
#define STR_PTR_P_SET(p, v) (((struct iovec*)p)->iov_base = v)
#define STR_LEN(s) ((size_t)((struct iovec*)&s)->iov_len)
#define STR_LEN_P(p) ((size_t)((struct iovec*)p)->iov_len)
#define STR_LEN_SET(s, l) (((struct iovec*)&s)->iov_len = l)
#define STR_LEN_P_SET(p, l) (((struct iovec*)p)->iov_len = l)

typedef struct irc_msg_in_buf_s
{
	uint8_t			  * data;		/* pointer to data buffer */
	size_t				size;		/* number of bytes in buffer */

} irc_msg_in_buf_t;

typedef struct irc_msg_out_buf_s
{
	struct iovec	  * iov;		/* list of iovec structures */
	size_t				nvec;		/* number of iovec structures */
    list_t              strs;       /* keep track of any dyn allocated strings */

} irc_msg_out_buf_t;

typedef struct irc_msg_h_s			/* host */
{
	irc_host_type_t		kind;		/* kind of host field */
    sockaddr_t          addr;       /* address */
    irc_str_ref_t       hostname;   /* DNS hostname */

} irc_msg_h_t;

typedef struct irc_msg_nuh_s		/* (nickname [ [ "!" user ] "@" host ] ) */
{
    irc_str_ref_t       nickname;
    irc_str_ref_t       user;
	irc_msg_h_t			host;

} irc_msg_nuh_t;

typedef struct irc_msg_prefix_s		/* servername / nuh */
{
	irc_prefix_type_t	kind;		/* kind of msg prefix */
    irc_str_ref_t       servername;
	irc_msg_nuh_t		nuh;

} irc_msg_prefix_t;

typedef struct irc_msg_s
{
	irc_msg_in_buf_t	in;			/* used when reading and parsing messages from stream */
	irc_msg_out_buf_t	out;		/* the buffer used for sending sending */

	/* the second pass is to parse the sub-parts of the major parts */
	irc_msg_prefix_t	prefix;		/* prefix specified in the prefix */
	irc_command_t		cmd;		/* the command/reply */
	list_t				params;		/* list of *irc_str_ref_t */
    int_t               trailing;   /* is last param a trailing param? */

} irc_msg_t;

/* create a new message */
irc_msg_t * irc_msg_new();

/* create a new message from buffer */
irc_msg_t * irc_msg_new_from_data( uint8_t const * const data, size_t const size );

/* free a message */
void irc_msg_delete( void * m );

/* parse an incoming msg buffer into a message */
irc_ret_t irc_msg_parse( irc_msg_t * const msg );

/* compile the message into a string buffer for sending */
irc_ret_t irc_msg_compile( irc_msg_t * const msg );

void irc_msg_log( irc_msg_t const * const msg );

/* initialize the message in one pass */
irc_ret_t irc_msg_set_all( irc_msg_t * const msg,
					       irc_command_t const cmd,
                           irc_msg_prefix_t* const prefix,
                           uint_t const count,
                           ... );

/* add a parameter */
irc_ret_t irc_msg_add_parameter( irc_msg_t * const msg, 
                                 uint8_t const * const param );

/* add a trailing parameter */
irc_ret_t irc_msg_set_trailing( irc_msg_t * const msg,
                                uint8_t const * const param );

/* returns a pointer to the trailing parameter if it exists */
uint8_t * irc_msg_get_trailing( irc_msg_t * const msg );

/* returns the parameter at the given index */
uint8_t * irc_msg_get_param( irc_msg_t * const msg, int_t const idx );

/* "closes" a message and prepares it to be sent */
irc_ret_t irc_msg_finalize( irc_msg_t * const msg );

/* flatten finalized message into a string */
irc_ret_t irc_msg_flatten( irc_msg_t * const msg, uint8_t ** s );

#endif
