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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>

#define  DEBUG_ON

#include <cutil/debug.h>
#include <cutil/macros.h>
#include <cutil/list.h>
#include <cutil/events.h>
#include <cutil/socket.h>

#include "commands.h"
#include "msg.h"
#include "conn.h"

#define min(x, y) (((x) < (y)) ? (x) : (y))

#define DEFAULT_WRITE_QUEUE_SIZE (8)

struct irc_conn_s
{
	/* event loop */
	evt_loop_t*		el;				/* event loop pointer */

	/* callbacks and user data */
	irc_conn_ops_t	ops;
	void*			user_data;		/* user data */

	/* socket */
	int				disconnect;		/* pending disconnect? */
	socket_t*		socket;			/* socket to the server */

	/* write queue of irc messages */
	list_t			wmsgs;			/* list of messages pending send */

	/* next message we're decoding */
	irc_msg_t		msg;			/* pending message */

	/* "ring" buffer for reading data from socket */
	uint8_t			buf[IRC_READ_BUF]; /* read buffer */
	uint8_t*		startp;			/* start of the pending message */
	uint8_t*		scanp;			/* pointer to byte we haven't scanned */
	uint8_t*		inp;			/* pointer to where incoming data gets written */
	uint8_t*		warnp;			/* pointer to the guard band in the buffer */
};


static socket_ret_t socket_connect_fn( socket_t * const s,
									   void * user_data )
{
	irc_conn_t * conn = (irc_conn_t*)user_data;

	DEBUG( "irc connection established\n" );

	/* pass the event on to our client */
	if ( conn->ops.connected != NULL )
	{
		(*(conn->ops.connected))( conn, conn->user_data );
	}
	
	return SOCKET_OK;
}


static socket_ret_t socket_disconnect_fn( socket_t * const s,
										  void * user_data )
{
	irc_conn_t * conn = (irc_conn_t*)user_data;

	DEBUG( "irc connection terminated\n" );

	/* pass the event on to our client */
	if ( conn->ops.disconnected != NULL )
	{
		(*(conn->ops.disconnected))( conn, conn->user_data );
	}
	
	return SOCKET_OK;
}


static socket_ret_t socket_error_fn( socket_t * const s,
									 int errno,
									 void * user_data )
{
	irc_conn_t * conn = (irc_conn_t*)user_data;

	DEBUG( "irc error callback: %d -- %s\n", errno, strerror(errno) );

	/* if we are pending a disconnect, just close the socket */
	if ( conn->disconnect )
	{
		DEBUG( "received error during pending disconnect, closing socket\n" );
		socket_disconnect( conn->socket );
	}
	
	return SOCKET_OK;
}


static irc_ret_t irc_receive_data( irc_conn_t * const conn, size_t * const nread )
{
	irc_ret_t ret = IRC_OK;
	size_t nspace = 0;
	size_t nleft = 0;
	size_t nr = 0;
	size_t recvd = 0;

	CHECK_PTR_RET( conn, IRC_BADPARAM );
	CHECK_PTR_RET( nread, IRC_BADPARAM );
	CHECK_RET( ((*nread) > 0), IRC_OK );

	/* how many more bytes will get us to the 512 max? */
	nspace = ( IRC_MSG_SIZE - (conn->inp - conn->startp) );
#if defined(PORTABLE_64_BIT)
	DEBUG( "%ld bytes of unscanned, %ld space\n", (int_t)(conn->inp - conn->startp), nspace );
#else
	DEBUG( "%d bytes of unscanned, %d space\n", (int_t)(conn->inp - conn->startp), nspace );
#endif

	/* we're going to try to read up to 512 boundary or what is available */
	nleft = min( nspace, (*nread) );

#if defined(PORTABLE_64_BIT)
	DEBUG( "nread = %ld, going to read %ld\n", (*nread), nleft );
#else
	DEBUG( "nread = %d, going to read %d\n", (*nread), nleft );
#endif

	while ( nleft > 0 )
	{
		nr = socket_read( conn->socket, conn->inp, nleft );

		if ( nr == 0 )
			break;

		conn->inp += nr;
		recvd += nr;
		nleft -= nr;
		(*nread) -= nr;
	}

#if defined(PORTABLE_64_BIT)
	DEBUG( "read %ld bytes from socket\n", recvd );
#else
	DEBUG( "read %d bytes from socket\n", recvd );
#endif

	return IRC_OK;
}


static irc_ret_t irc_scan_for_msg( irc_conn_t * const conn )
{
	int found_r = FALSE;
	irc_msg_in_buf_t * m = &conn->msg.in;
	uint8_t *p = conn->scanp;

	CHECK_PTR_RET( conn, IRC_BADPARAM );

	while ( p < conn->inp )
	{
		if ( found_r )
		{
			if ( *p == '\n' )
			{
				/* we found the end of a msg */

				++p; /* now points to byte after msg */
				
				/* set up our irc message structure */
				m->data = conn->startp;
				m->size = (size_t)((void*)p - (void*)m->data);

				/* update the irc conn state */
				conn->startp = p;
#if defined(PORTABLE_64_BIT)
				DEBUG("scanned %ld bytes, found full message, %ld left to scan\n", (int_t)(p - conn->scanp), (int_t)(conn->inp - p));
#else
				DEBUG("scanned %d bytes, found full message, %d left to scan\n", (int_t)(p - conn->scanp), (int_t)(conn->inp - p));
#endif
				conn->scanp = p;
			
				/* we have found a full message...if we haven't scanned
				 * everything we've read, then reaturn IRC_CONTINUE, otherwise
				 * that's it and we return IRC_OK */
				return ( (p < conn->inp) ? IRC_CONTINUE : IRC_OK );
			}
			else
			{
				found_r = FALSE;
			}
		}
		else
		{
			if ( *p == '\r' )
			{
				found_r = TRUE;
			}
		}
		
		++p;
	}

#if defined(PORTABLE_64_BIT)
	DEBUG("scanned %ld bytes, didn't see full message, %ld left to scan\n", (int_t)(p - conn->scanp), (int_t)(conn->inp - p));
#else
	DEBUG("scanned %d bytes, didn't see full message, %d left to scan\n", (int_t)(p - conn->scanp), (int_t)(conn->inp - p));
#endif

	/* store where we are stopping the scan */
	conn->scanp = p;

	return IRC_MSG_MOREDATA;
}


/* receive an IRC message from the server */
static irc_ret_t irc_receive_msg( irc_conn_t* const conn, size_t * const nread )
{
	irc_ret_t ret = IRC_OK;
	size_t remsize = 0;
	size_t scansize = 0;

	CHECK_PTR_RET( conn, IRC_BADPARAM );
	CHECK_PTR_RET( nread, IRC_BADPARAM );
	
	if ( ((*nread) > 0) && ((conn->inp - conn->scanp) == 0) )
	{
		/* read the next chunk of data from the socket */
		irc_receive_data( conn, nread );
	}

	/* scan the data to see if there is a message */
	ret = irc_scan_for_msg( conn );

	/* parse the message if the scanner found a whole message */
	if ( (ret == IRC_OK) || (ret == IRC_CONTINUE) )
	{
		if ( irc_msg_parse( &conn->msg ) == IRC_OK )
		{
			DEBUG("received message:\n");
			irc_msg_log( &(conn->msg) );
		}
		else
		{
			WARN( "received message failed to parse\n" );
		}
	}
	
	/* we need to handle wrapping on the buffer properly.  if there is remainder
	 * data, ret == IRC_MSG_MOREDATA.  if there isn't any remainder data then
	 * ret == IRC_OK.  in both cases we need to look at where conn->startp is.
	 * if it is >= conn->warnp, we need to wrap it around the end of the buffer. */
	if ( conn->startp >= conn->warnp )
	{
		DEBUG("XXX into guard band, wrapping\n");
		remsize = (conn->inp - conn->startp);
		scansize = (conn->scanp - conn->startp);

#if defined(PORTABLE_64_BIT)
		DEBUG("XXX copying %ld bytes to the start of buffer\n", remsize);
#else
		DEBUG("XXX copying %d bytes to the start of buffer\n", remsize);
#endif
		/* copy the remainder data to the start of the buffer */
		MEMCPY( (void*)conn->buf, conn->startp, remsize );

		conn->startp = conn->buf;
		conn->scanp = conn->buf + scansize;
		conn->inp = conn->buf + remsize;
	}

	return ret;
}


static int32_t socket_read_fn( socket_t * const s,
							   size_t nread,
							   void * user_data )
{
	irc_ret_t ret = IRC_OK;
	irc_conn_t * conn = (irc_conn_t*)user_data;
	size_t ntmp = nread;

#if defined(PORTABLE_64_BIT)
	DEBUG( "irc read %ld callback\n", nread );
#else
	DEBUG( "irc read %d callback\n", nread );
#endif

	if ( conn->disconnect )
	{
		WARN("received socket READ during pending disconnect\n" );
	}

	do
	{
		DEBUG( "trying to receive a message\n" );
		ret = irc_receive_msg( conn, &ntmp );

		if ( ( ret == IRC_OK ) || ( ret == IRC_CONTINUE ) )
		{
			/* call the message callback */
			if ( conn->ops.message_in != NULL )
			{
				(*(conn->ops.message_in))(conn, &(conn->msg), conn->user_data);
			}

			/* the message has been processed so clear out the struct */
			MEMSET( (void*)(&conn->msg), 0, sizeof(irc_msg_t) );
		}
		else if ( ret == IRC_MSG_MOREDATA )
		{
			DEBUG( "waiting for the rest of the message\n" );
			return 0;
		}
		else
		{
			DEBUG( "error from irc_receive_msg()\n" );
			return 0;
		}

	} while( ret == IRC_CONTINUE );
	
	return 0;
}


static int32_t socket_write_fn( socket_t * const s,
								uint8_t const * const buffer,
								void * user_data )
{
	irc_msg_t * msg = NULL;
	irc_conn_t * conn = (irc_conn_t*)user_data;

	DEBUG( "irc write callback\n" );

	/* get the irc_msg_t pointer from the head of the list */
	msg = (irc_msg_t*)list_get_head( &(conn->wmsgs) );

	/* check to make sure it matches what we're being given */
	if ( (void*)msg->out.iov == (void*)buffer )
	{
		DEBUG( "message write complete\n" );

		/* clean up */
		list_pop_head( &(conn->wmsgs) );

		/* call the message out callback */
		if ( conn->ops.message_out != NULL )
		{
			(*(conn->ops.message_out))(conn, msg, conn->user_data);
		}
	}
	else
	{
		WARN( "received write callback with buffer mismatch\n" );
	}

	if ( conn->disconnect && (list_count( &(conn->wmsgs) ) == 0) )
	{
		DEBUG("all pending message sends have completed, now we can disconnect\n");
		/* all messages have been written */
		socket_disconnect( conn->socket );
	}

	return 0;
}


static void irc_conn_initialize( irc_conn_t * const conn,
								 irc_conn_ops_t * const ops,
								 evt_loop_t * const el,
								 void * user_data )
{
	static socket_ops_t sock_ops = 
	{ 
		&socket_connect_fn, 
		&socket_disconnect_fn, 
		&socket_error_fn, 
		&socket_read_fn, 
		&socket_write_fn 
	};

	/* zero out the memory */
	MEMSET( (void*)conn, 0, sizeof( irc_conn_t ) );

	/* store the event loop */
	conn->el = el;

	/* store the callbacks */
	MEMCPY( &(conn->ops), ops, sizeof(irc_conn_ops_t) );
	conn->user_data = user_data;
	
	/* initialize the socket */
	conn->disconnect = FALSE;
	conn->socket = socket_new( SOCKET_TCP, &sock_ops, conn->el, conn );

	/* initialize the write msg list */
	list_initialize( &(conn->wmsgs), DEFAULT_WRITE_QUEUE_SIZE, NULL );

	/* initialize read buffer pointers */
	conn->startp = conn->scanp = conn->inp = conn->buf;

	/* initialize the warning marker pointer */
	conn->warnp = (conn->buf + (IRC_READ_BUF - (2 * IRC_MSG_SIZE)));
}


irc_conn_t* irc_conn_new( irc_conn_ops_t * const ops,	/* callbacks for irc messages */
						  evt_loop_t * const el,	/* event loop to use */
						  void * user_data )		/* user data passed back to callbacks */
{
	irc_conn_t* conn = NULL;
	
	CHECK_PTR_RET( ops, NULL );
	CHECK_PTR_RET( el, NULL );

	/* allocate the irc socket struct */
	conn = MALLOC( sizeof(irc_conn_t) );
	CHECK_PTR_RET_MSG( conn, NULL, "failed to allocate irc struct\n" );

	irc_conn_initialize( conn, ops, el, user_data );

	return conn;
}


static void irc_conn_deinitialize( irc_conn_t * const conn )
{
	CHECK_PTR( conn );
	CHECK_MSG( !socket_is_connected( conn->socket ), "deinitializing active irc conn\n" );

	/* we're disconnected */
	DEBUG("irc connection deinitializing\n");

	/* clean up the socket */
	socket_delete( (void*)conn->socket );
	conn->socket = NULL;

	/* clean up write list */
	list_deinitialize( &(conn->wmsgs) );
}

/* these function allocate/deallocate the opaque handle */
void irc_conn_delete(void * c)
{
	irc_conn_t* conn = (irc_conn_t*)c;
	CHECK_PTR( conn );
	CHECK_MSG( !socket_is_connected( conn->socket ), "deleting active irc conn\n" );

	/* deinitialize, don't wait for messages to be written */
	irc_conn_deinitialize( conn );

	FREE( conn );
}


/* these functions handle connecting/disconnecting to/from servers */
irc_ret_t irc_conn_connect( irc_conn_t* const conn,				/* irc context */
							int8_t const * const server_host,	/* hostname of the server */
							uint16_t const server_port)			/* port of the server */
{
	CHECK_PTR_RET(conn, IRC_BADPARAM);
	
	/* disconnect any existing socket if needed */
	if ( socket_is_connected( conn->socket ) )
	{
		WARN( "socket already connected\n" );
		return IRC_ERR;
	}
	
	if ( socket_connect( conn->socket, server_host, server_port ) != SOCKET_OK )
		return IRC_SOCKET_ERROR;

	return IRC_OK;
}


irc_ret_t irc_conn_disconnect( irc_conn_t* const conn, int do_wait )
{
	CHECK_PTR_RET( conn, IRC_BADPARAM );

	/* set pending disconnect flag */
	conn->disconnect = TRUE;

	if ( !do_wait || (list_count( &(conn->wmsgs) ) == 0) )
	{
		DEBUG("no messages waiting, closing socket immediately\n");

		/* disconnect the socket */
		socket_disconnect( conn->socket );
	}
	else
	{
		DEBUG("waiting for all messages to send\n");
	}
	
	return IRC_OK;
}


/* send the specified IRC message to the server */
irc_ret_t irc_conn_send_msg( irc_conn_t* const conn,
							 irc_msg_t* const msg )
{
	CHECK_PTR_RET(conn, IRC_BADPARAM);
	CHECK_PTR_RET(msg, IRC_BADPARAM);

	if ( conn->disconnect )
	{
		DEBUG("blocking message send due to pending disconnect\n");
		return IRC_ERR;
	}

	DEBUG("irc_conn_send_msg()\n");

	if(IRC_OK != irc_msg_finalize(msg))
	{
		WARN("failed to finalize message before sending\n");
		return IRC_ERR;
	}

	/* remember the message being queued up to write */
	list_push_tail( &(conn->wmsgs), (void*)msg );

	DEBUG("sending message:\n");
	irc_msg_log( msg );

	/* queue up the msg for writing using gather I/O for speed */
	socket_writev( conn->socket, msg->out.iov, msg->out.nvec );
	
	return IRC_OK;
}


