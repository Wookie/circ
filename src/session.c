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
#include <assert.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>

#define DEBUG_ON

#include <cutil/debug.h>
#include <cutil/macros.h>
#include <cutil/events.h>
#include <cutil/btree.h>
#include <cutil/pair.h>

#include "commands.h"
#include "msg.h"
#include "conn.h"
#include "session.h"

#define CHECK_HANDLER_PRAMS CHECK_PTR_RET( session, IRC_BADPARAM ); \
							CHECK_PTR_RET( msg, IRC_BADPARAM );

struct irc_session_s
{
	irc_session_state_t state;					/* session state */
	evt_loop_t*			el;						/* event loop */
	irc_conn_t*			conn;					/* irc connection */
	ht_t*				settings;				/* hashtable of settings */
	ht_t*				servers;				/* hashtable of servers in the network */
	ht_t*				handlers;				/* hashtable of event handlers */
	void *				user_data;				/* handler context */
};

/* forward declare the PING handler */
/*static HANDLER_FN( NULL, PING );*/
static irc_ret_t fn_NULL_PING_fn( irc_session_t * const session,
								  irc_msg_t * const msg,
								  void * user_data );

/* forward declare the helper functions */
static uint32_t fnv_key_hash(void const * const key);
static int string_eq( void const * const l, void const * const r );
static int int_less( void * l, void * r );
static uint_t setting_hash_fn( void const * const key );
static int setting_match_fn( void const * const l, void const * const r );
static void setting_delete_fn( void * p );

/* handles calling the handlers associated with the cmd */
static irc_ret_t irc_session_call_handler( irc_session_t * const session, 
										   irc_msg_t * const msg,
										   irc_command_t const cmd )
{
	ht_itr_t itr, end;
	irc_event_cb_t * cb = NULL;
	
	CHECK_PTR_RET( session, IRC_BADPARAM );
	CHECK_PTR_RET( session->handlers, IRC_BADPARAM );

	itr = ht_itr_begin( session->handlers );
	end = ht_itr_end( session->handlers );
	for ( ; !ITR_EQ( itr, end ); itr = ht_itr_next( session->handlers, itr ) )
	{
		/* get the next handler */
		cb = (irc_event_cb_t*)ht_get( session->handlers, itr );

		if ( cb == NULL )
			continue;

		if ( irc_event_cb_get_cmd( cb ) != cmd )
			continue;

		/* call the callback */
		irc_event_cb_call_fn( cb, msg );
	}

	return IRC_OK;
}

static void send_pass( irc_session_t * const session )
{
	irc_msg_t * pass = NULL;
	int8_t * server_pass = NULL;
	CHECK_PTR( session );

	server_pass = irc_session_get( session, SERVER_PASS );

	/* send the PASS command */
	pass = irc_msg_new();
	irc_msg_initialize( pass, PASS, NULL, 1, server_pass );

	/* send the PASS command */
	irc_conn_send_msg( session->conn, pass );
}

static void send_nick( irc_session_t * const session )
{
	irc_msg_t * nick = NULL;
	int8_t * nick_name = NULL;
	CHECK_PTR( session );

	nick_name = irc_session_get( session, NICK_NAME );

	/* send the NICK command */
	nick = irc_msg_new();
	irc_msg_initialize( nick, NICK, NULL, 1, nick_name );

	/* send the NICk command */
	irc_conn_send_msg( session->conn, nick );
}

static void send_user( irc_session_t * const session )
{
	irc_msg_t * user = NULL;
	int8_t * user_name = NULL;
	CHECK_PTR( session );

	user_name = irc_session_get( session, USER_NAME );

	/* send the USER command */
	user = irc_msg_new();
	irc_msg_initialize( user, USER, NULL, 3, user_name, "0", "*" );
	irc_msg_set_trailing( user, user_name );

	/* send the USER command */
	irc_conn_send_msg( session->conn, user );
}

static void send_quit( irc_session_t * const session )
{
	irc_msg_t * quit = NULL;
	int8_t * quit_msg = NULL;
	CHECK_PTR( session );

	quit_msg = irc_session_get( session, QUIT_MSG );

	/* send QUIT */
	quit = irc_msg_new();
	irc_msg_initialize( quit, QUIT, NULL, 0 );
	irc_msg_set_trailing( quit, quit_msg );

	/* send the QUIT command */
	irc_conn_send_msg( session->conn, quit );
}


static irc_ret_t irc_conn_message_in( irc_conn_t * const conn, 
									  irc_msg_t * const msg, 
									  void * user_data  )
{
	irc_session_t * session = (irc_session_t*)user_data;
	CHECK_PTR_RET( session, IRC_BADPARAM );
	CHECK_PTR_RET( msg, IRC_BADPARAM );

	/* call registered handlers */
	irc_session_call_handler( session, msg, msg->cmd );

	/* call the catch-all handlers */
	irc_session_call_handler( session, msg, ANYCMD );

	return IRC_OK;
}

static irc_ret_t irc_conn_message_out( irc_conn_t * const conn,
									   irc_msg_t * const msg,
									   void * user_data )
{
	irc_session_t * session = (irc_session_t*)user_data;
	CHECK_PTR_RET( session, IRC_BADPARAM );

	if ( session->state == IRC_SESSION_QUIT )
	{
		/* our QUIT command has been sent, now we're pending disconnect */
		session->state = IRC_SESSION_PENDING_DISCONNECT;
	}

	/* free the message */
	irc_msg_delete( msg );

	return IRC_OK;
}

static irc_ret_t irc_conn_connected( irc_conn_t * const conn, 
									 void * user_data )
{
	irc_session_t * session = (irc_session_t*)user_data;
	int8_t * password = NULL;
	CHECK_PTR_RET( session, IRC_BADPARAM );

	/* should only receive these when disconnected */
	ASSERT( session->state == IRC_SESSION_DISCONNECTED );

	/* we have a connection to the server, now we must register it */
	session->state = IRC_SESSION_CONNECTED;

	/* kick off the IRC connection registration */
	if ( irc_session_get( session, SERVER_PASS ) != NULL )
	{
		/* send the PASS command */
		send_pass( session );
	}
	else
	{
		/* send the NICK command */
		send_nick( session );
	}

	/* send the USER command */
	send_user( session );

	return IRC_OK;
}

static irc_ret_t irc_conn_disconnected( irc_conn_t * const conn, 
										void * user_data )
{
	irc_session_t * session = (irc_session_t*)user_data;
	CHECK_PTR_RET( session, IRC_BADPARAM );

	if ( session->state != IRC_SESSION_PENDING_DISCONNECT )
	{
		WARN("got disconnected unexpectedly\n");
	}

	session->state = IRC_SESSION_DISCONNECTED;

	DEBUG("session has been taken down completely\n");

	/* call "disconnected" handler */
	irc_session_call_handler( session, NULL, SESSION_DISCONNECTED );

	return IRC_OK;
}

/* send the specified IRC command to the server */
irc_ret_t irc_session_send_msg( irc_session_t * const session, irc_msg_t * const msg )
{
	CHECK_PTR_RET( session, IRC_BADPARAM );
	CHECK_PTR_RET( msg, IRC_BADPARAM );
	return irc_conn_send_msg( session->conn, msg );
}

static int irc_session_initialize( irc_session_t * const session,
								   evt_loop_t * const el,
								   void * user_data )
{
	irc_ret_t ret = IRC_OK;
	irc_event_cb_t * ping_cb = NULL;
	irc_event_cb_t * rpl_welcome_cb = NULL;
	irc_event_cb_t * nick_cb = NULL;
	irc_event_cb_t * privmsg_cb = NULL;
	static irc_conn_ops_t conn_ops = 
	{
		&irc_conn_message_in,
		&irc_conn_message_out,
		&irc_conn_connected,
		&irc_conn_disconnected
	};

	CHECK_PTR_RET( session, FALSE );
	CHECK_PTR_RET( el, FALSE );

	/* zero everything out */
	MEMSET( (void*)session, 0, sizeof( irc_session_t ) );

	/* store the session state */
	session->state = IRC_SESSION_DISCONNECTED;

	/* store the event loop handle */
	session->el = el;

	/* create the irc connection */
	session->conn = irc_conn_new( &conn_ops, el, (void*)session );
	CHECK_PTR_RET( session->conn, FALSE );

	/* create the settings hashtable */
	session->settings = ht_new( 64, &setting_hash_fn, &setting_match_fn, &setting_delete_fn );
	CHECK_PTR_RET( session->settings, FALSE );

	/* create the handlers hashtable */
	session->handlers = ht_new( 8, &irc_event_cb_hash, &irc_event_cb_match, &irc_event_cb_delete );
	CHECK_PTR_RET( session->handlers, FALSE );

	/* store the handler context */
	session->user_data = user_data;

	/* register PING handler */
	ping_cb = NEW_HANDLER( PING, session, NULL );
	CHECK_RET( (IRC_OK == irc_session_set_handler( session, ping_cb )), FALSE );

	/* register RPL_WELCOME handler */
	rpl_welcome_cb = NEW_HANDLER( RPL_WELCOME, session, NULL );
	CHECK_RET( (IRC_OK == irc_session_set_handler( session, rpl_welcome_cb )), FALSE );

	/* register NICK handler */
	nick_cb = NEW_HANDLER( NICK, session, NULL );
	CHECK_RET( (IRC_OK == irc_session_set_handler( session, nick_cb)), FALSE );

	/* register PRIVMSG handler */
	privmsg_cb = NEW_HANDLER( PRIVMSG, session, NULL );
	CHECK_RET( (IRC_OK == irc_session_set_handler( session, privmsg_cb)), FALSE );

	return TRUE;
}


irc_session_t * irc_session_new( evt_loop_t * const el,
								 void * user_data )
{
	irc_session_t * session = NULL;

	CHECK_PTR_RET( el, NULL );

	/* allocate the session struct */
	session = CALLOC( 1, sizeof(irc_session_t) );
	CHECK_PTR_RET_MSG( session, NULL, "failed to allocate session struct\n" );

	if ( !irc_session_initialize( session, el, user_data ) )
	{
		FREE( session );
		return NULL;
	}

	return session;
}


static void irc_session_deinitialize( irc_session_t * const session )
{
	CHECK_PTR( session );
	CHECK_MSG( session->state == IRC_SESSION_DISCONNECTED, "deinitializing active session\n" );

	DEBUG("deinitializing session\n");

	/* must be disconnected to deinitialize everything */
	irc_conn_delete( (void*)session->conn );

	/* clean up hash tables */
	ht_delete( session->settings );
	ht_delete( session->handlers );

	/* drop pointer to context */
	session->user_data = NULL;
}


void irc_session_delete( void * s )
{
	irc_session_t * session = (irc_session_t*)s;
	CHECK_PTR( session );
	CHECK_MSG( session->state == IRC_SESSION_DISCONNECTED, "deleting active session\n" );

	/* deinit the session, don't sent the QUIT */
	irc_session_deinitialize( session );

	FREE( session );
}

irc_ret_t irc_session_set( irc_session_t * const session,
						   irc_session_setting_t const setting,
						   void * const value )
{
	pair_t * p, * r = NULL;
	ht_itr_t itr;
	CHECK_PTR_RET( session, IRC_BADPARAM );
	CHECK_PTR_RET( value, IRC_BADPARAM );
	p = pair_new( (void*)setting, (void*)value );
	itr = ht_find( session->settings, (void*)p );
	r = (pair_t*)ht_get( session->settings, itr );
	ht_remove( session->settings, itr );
	setting_delete_fn( r );
	ht_insert( session->settings, p );
	return IRC_OK;
}


void * irc_session_get( irc_session_t * const session,
					    irc_session_setting_t const setting )
{
	pair_t * p = NULL;
	ht_itr_t itr;
	CHECK_PTR_RET( session, NULL );
	p = pair_new( (void*)setting, NULL );
	itr = ht_find( session->settings, (void*)p );
	pair_delete( p );
	p = ht_get( session->settings, itr );
	return (void*)pair_second( p );
}


irc_ret_t irc_session_set_handler( irc_session_t * const session,
								   irc_event_cb_t * const cb )
{
	CHECK_PTR_RET( session, IRC_BADPARAM );
	CHECK_PTR_RET( cb, IRC_BADPARAM );

	CHECK_RET( ht_insert( session->handlers, (void*)cb ), IRC_ERR );

	return IRC_OK;
}

irc_ret_t irc_session_clear_handler( irc_session_t * const session,
									 uint8_t const * const name )
{
	ht_itr_t itr;
	CHECK_PTR_RET( session, IRC_BADPARAM );
	CHECK_PTR_RET( name, IRC_BADPARAM );

	/* look up the event cb struct */
	itr = irc_event_cb_ht_find( session->handlers, name );

	/* try to call the callback */
	CHECK_RET( ht_remove( session->handlers, itr ), IRC_ERR );

	return IRC_OK;
}

irc_ret_t irc_session_connect( irc_session_t * const session )
{
	int8_t * host;
	uint16_t port;
	CHECK_PTR_RET( session, IRC_BADPARAM );

	host = (int8_t*)irc_session_get( session, SERVER_HOST );
	port = *((uint16_t*)irc_session_get( session, SERVER_PORT ));

	/* try to initiate an irc connection */
	DEBUG( "attempting connection to: %s:%d\n", host, port );
	if ( irc_conn_connect( session->conn, host, port ) != IRC_OK )
	{
		WARN(" failed to create session connection\n" );
		return IRC_ERR;
	}

	return IRC_OK;
}

irc_ret_t irc_session_disconnect( irc_session_t * const session, int do_quit )
{
	CHECK_PTR_RET( session, IRC_BADPARAM );

	if ( session->state >= IRC_SESSION_CONNECTED )
	{
		if ( do_quit && ( session->state == IRC_SESSION_ACTIVE ) )
		{
			DEBUG("sending QUIT to kick off orderly disconnect\n");

			/* set out state before sending the command */
			session->state = IRC_SESSION_QUIT;
			send_quit( session );

			/* disconnect, wait for all messages to be transmitted */
			irc_conn_disconnect( session->conn, TRUE );

			return IRC_OK;
		}
	}
	
	DEBUG("don't have registered connection so tear down immediately\n");

	if ( session->state == IRC_SESSION_PENDING_DISCONNECT )
	{
		/* have already tried to disconnect... */
		session->state = IRC_SESSION_DISCONNECTED;

		DEBUG("forcing session takedown\n");

		/* call "disconnected" handler */
		irc_session_call_handler( session, NULL, SESSION_DISCONNECTED );

	}
	else
	{
		/* haven't tried to disconnect yet... */
		DEBUG("beginning connection disconnect\n");

		/* move to pending disconnect state */
		session->state = IRC_SESSION_PENDING_DISCONNECT;

		/* disconnect, DON'T wait for all messages to be transmitted */
		irc_conn_disconnect( session->conn, FALSE );
	}

	return IRC_OK;
}

/*************************************************/
/********************** static helper functions **/
/*************************************************/

#define FNV_PRIME (0x01000193)
static uint32_t fnv_key_hash(void const * const key)
{
    uint32_t hash = 0x811c9dc5;
	uint8_t const * p = (uint8_t const *)key;
	while ( (*p) != '\0' )
	{
		hash *= FNV_PRIME;
		hash ^= *p++;
	}
	return hash;
}

static int string_eq( void const * const l, void const * const r )
{
	return ( 0 == strcmp(C(l), C(r)) );
}

static int int_less( void * l, void * r )
{
	int li = (int)l;
	int ri = (int)r;

	if ( li < ri )
		return -1;
	else if ( li > ri )
		return 1;
	return 0;
}

static uint_t setting_hash_fn( void const * const key )
{
	CHECK_PTR_RET( key, 0 );
	return (uint_t)pair_first((pair_t*)key);
}

static int setting_match_fn( void const * const l, void const * const r )
{
	CHECK_PTR_RET( l, FALSE );
	CHECK_PTR_RET( r, FALSE );
	return ((uint_t)pair_first((pair_t*)l) == (uint_t)pair_first((pair_t*)r));
}

static void setting_delete_fn( void * p )
{
	pair_t * pair = (pair_t*)p;
	CHECK_PTR( pair );

	FREE( pair_second( p ) );
	pair_delete( p );
}

/* this gets called when we receive a PING message from the server */
static HANDLER_FN( NULL, PING )
{
	int8_t const * dest;
	irc_msg_t * pong = NULL;

	CHECK_RET( (msg->cmd == PING), IRC_BADPARAM );

	/* get a pointer to the last part of the PING message */
	dest = (msg->trailing != NULL) ? msg->trailing : msg->parameters[msg->num_params-1];
	DEBUG("received PING from %s\n", dest);

	/* send PONG */
	pong = irc_msg_new();
	irc_msg_initialize( pong, PONG, NULL, 1, dest );

	/* send the PONG command */
	irc_conn_send_msg( session->conn, pong );

	return IRC_OK;
}

/* this gets called when the connection is fully registered */
static HANDLER_FN( NULL, RPL_WELCOME )
{
	CHECK_RET( (msg->cmd == RPL_WELCOME), IRC_BADPARAM );

	/* call the "connected" event handler */
	irc_session_call_handler( session, msg, SESSION_CONNECTED );

	return IRC_OK;
}

/* this gets called when a user changes their nick */
static HANDLER_FN( NULL, NICK )
{
	CHECK_RET( (msg->cmd == NICK), IRC_BADPARAM );

	/* call the "on_nick" event handler */
	irc_session_call_handler( session, msg, SESSION_ON_NICK );

	return IRC_OK;
}

/* this gets called whenever a PRIVMSG comes to us */
static HANDLER_FN( NULL, PRIVMSG )
{
	uint8_t * p = NULL;
	CHECK_RET( (msg->cmd == PRIVMSG), IRC_BADPARAM );

	/* we need to figure out if this is a private or public message.  if first
	 * parameter is equal to our current nick, then it is a private message to
	 * us, otherwise it is public. */
	CHECK_RET( (msg->num_params > 0), IRC_BADPARAM );

	p = msg->parameter[0];
	while( *p && ((

	return IRC_OK;
}


#ifdef UNIT_TESTING

#include <CUnit/Basic.h>

void test_session_private_functions( void )
{
}

#endif

