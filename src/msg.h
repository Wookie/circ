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

typedef enum irc_origin_type_e
{
	CONN_ORIGIN = 0,				/* no prefix in message, origin from connection */
	SERVERNAME_ORIGIN = 1,			/* prefix is server name */
	NUH_ORIGIN = 2,					/* prefix is name [ [ '!' user] '@' host ] */

	LAST_ORIGIN,
	FIRST_ORIGIN = CONN_ORIGIN,
	NUM_ORIGIN = LAST_ORIGIN - FIRST_ORIGIN

} irc_origin_type_t;

#define IS_VALID_ORIGIN(x) ((x >= FIRST_ORIGIN) && (x < LAST_ORIGIN))

typedef struct irc_msg_in_buf_s
{
	uint8_t			  * data;		/* pointer to data buffer */
	size_t				size;		/* number of bytes in buffer */

} irc_msg_in_buf_t;

typedef struct irc_msg_out_buf_s
{
	struct iovec	  * iov;		/* list of iovec structures */
	size_t				nvec;		/* number of iovec structures */

} irc_msg_out_buf_t;

typedef struct irc_msg_h_s			/* host */
{
	irc_host_type_t		kind;		/* kind of host field */
	struct in_addr		v4;			/* IPv4 address */
	struct in6_addr		v6;			/* IPv6 address */
	uint8_t			  * hostname;	/* DNS hostname */

} irc_msg_h_t;

typedef struct irc_msg_nuh_s		/* (nickname [ [ "!" user ] "@" host ] ) */
{
	uint8_t			  * nickname;			
	uint8_t			  * user;
	irc_msg_h_t			host;

} irc_msg_nuh_t;

typedef struct irc_msg_origin_s		/* servername / nuh */
{
	irc_origin_type_t	kind;		/* kind of msg origin */
	uint8_t			  * servername;
	irc_msg_nuh_t		nuh;

} irc_msg_origin_t;

typedef struct irc_msg_s
{
	irc_msg_in_buf_t	in;			/* used when reading and parsing messages from stream */
	irc_msg_out_buf_t	out;		/* the buffer used for sending sending */

	/* the second pass is to parse the sub-parts of the major parts */
	irc_msg_origin_t	origin;		/* origin specified in the prefix */
	irc_command_t		cmd;		/* the command/reply */
	list_t				params;		/* list of uint8_t * to each parameter */

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

#if 0
/* initialize the message in one pass */
irc_ret_t irc_msg_initialize(irc_msg_t* const msg,
							 irc_command_t const cmd,
							 uint8_t* const prefix,
							 int32_t const num_params,
							 ...);

/* add a parameter */
irc_ret_t irc_msg_add_parameter(irc_msg_t* const msg, uint8_t const * const param);

/* set the trailing parameter */
irc_ret_t irc_msg_set_trailing( irc_msg_t * const msg, uint8_t const * const trailing);

/* "closes" a message and prepares it to be sent */
irc_ret_t irc_msg_finalize( irc_msg_t * const msg );

/* set the command */
irc_ret_t irc_msg_set_command(irc_msg_t* const msg, irc_command_t const cmd);

#endif



#if 0

/* copy the msg */
void irc_msg_copy(irc_msg_t * const lhs, irc_msg_t const * const rhs);

						 
/* deinitialize the message */
irc_ret_t irc_msg_deinitialize(irc_msg_t* const msg);

/* clear the parameters */
irc_ret_t irc_msg_clear_parameters(irc_msg_t* const msg);

/* set a parameter */
irc_ret_t irc_msg_set_parameter(irc_msg_t* const msg, int32_t const index, int8_t const * const param);

#endif

#endif
