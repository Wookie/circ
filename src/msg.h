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

#define IRC_MSG_SIZE (512)
#define IRC_NUM_PARAMS (15)


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

typedef struct irc_msg_nuh_s		/* (nickname [ [ "!" user ] "@" host ] ) */
{
	uint8_t			  * nickname;			
	uint8_t			  * username;
	uint8_t			  * host;

} irc_msg_nuh_t;

typedef struct irc_msg_origin_s		/* servername / nuh */
{
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

/* free a message */
void irc_msg_delete( void * m );

/* parse an incoming msg buffer into a message */
irc_ret_t irc_msg_parse( irc_msg_t * const msg );

/* compile the message into a string buffer for sending */
irc_ret_t irc_msg_compile( irc_msg_t * const msg );

void irc_msg_log( irc_msg_t const * const msg );

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
