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
#include "channel.h"
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
	ht_t*				channels;				/* hashtable of channels */
	ht_t*				handlers;				/* hashtable of event handlers */
	void *				user_data;				/* handler context */
};

/* forward declare the message handlers */
static HANDLER_FN( PING );
static HANDLER_FN( RPL_WELCOME );
static HANDLER_FN( RPL_MYINFO );
static HANDLER_FN( MODE );
static HANDLER_FN( ANYCMD );

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


/* handles calling the handlers associated with the cmd */
static irc_ret_t irc_session_call_handler( irc_session_t * const session, 
										   irc_msg_t * const msg,
										   irc_command_t const cmd )
{
	bt_itr_t itr;
	ht_itr_t htitr;
	event_handler_fn handler_fn = NULL;
	pair_t * p = NULL;
	bt_t * handler_list = NULL;
	
	CHECK_PTR_RET( session, IRC_BADPARAM );
	CHECK_PTR_RET( session->handlers, IRC_BADPARAM );

	p = pair_new( (void*)cmd, NULL );
	htitr = ht_find( session->handlers, p );
	pair_delete( p );
	p = (pair_t*)ht_get( session->handlers, htitr );
	handler_list = p ? pair_second( p ) : NULL;
	CHECK_PTR_RET( handler_list, IRC_ERR );

	/* iterator through the list of handlers calling them until we either run out of
	 * handlers or one of the handlers returns IRC_DONE. */
	itr = bt_itr_begin( handler_list );
	for ( ; itr != bt_itr_end( handler_list ); itr = bt_itr_next( handler_list, itr ) )
	{
		handler_fn = (event_handler_fn)bt_itr_get( handler_list, itr );

		if ( handler_fn == NULL )
		{
			WARN("NULL handler fn pointer!\n");
			continue;
		}

		DEBUG( "Calling handler for %s\n", irc_cmd_get_string( cmd ) );
		if ( (*handler_fn)( session, msg, session->user_data ) == IRC_DONE )
			break;
	}

	return IRC_OK;
}


static void check_umodes( int8_t const * const modes )
{
	int i;
	for ( i = 0; i < IRC_UMODE_COUNT; ++i )
	{
		if ( modes[i] == '\0' )
			break;
		if ( !IS_UMODE( modes[i] ) )
			WARN( "unknown user mode: %c\n", modes[i] );
	}
}

static void check_cmodes( int8_t const * const modes )
{
	int i;
	for ( i = 0; i < IRC_CMODE_COUNT; ++i )
	{
		if ( modes[i] == '\0' )
			break;
		if ( !IS_CMODE( modes[i] ) )
			WARN( "unknown channel mode: %c\n", modes[i] );
	}
}

static void check_smodes( int8_t const * const modes )
{
	int i;
	for ( i = 0; i < IRC_SMODE_COUNT; ++i )
	{
		if ( modes[i] == '\0' )
			break;
		if ( !IS_SMODE( modes[i] ) )
			WARN( "unknown server mode: %c\n", modes[i] );
	}
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

static uint_t channel_hash_fn( void const * const key )
{
	return fnv_key_hash( irc_channel_get_name( (irc_channel_t*)key ) );
}

static int channel_match_fn( void const * const l, void const * const r )
{
	return strncmp( irc_channel_get_name( (irc_channel_t*)l ),
					irc_channel_get_name( (irc_channel_t*)r ),
					256 );
}

static uint_t handler_hash_fn( void const * const key )
{
	CHECK_PTR_RET( key, 0 );
	return (uint_t)pair_first((pair_t*)key);
}

static int handler_match_fn( void const * const l, void const * const r )
{
	CHECK_PTR_RET( l, FALSE );
	CHECK_PTR_RET( r, FALSE );
	return ((uint_t)pair_first((pair_t*)l) == (uint_t)pair_first((pair_t*)r));
}

static void handler_delete_fn( void * p )
{
	pair_t * pair = (pair_t*)p;
	CHECK_PTR( pair );

	bt_delete( pair_second( p ) );
	pair_delete( p );
}


static int irc_session_initialize( irc_session_t * const session,
								   evt_loop_t * const el,
								   void * user_data )
{
	irc_ret_t ret = IRC_OK;
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

	/* create the channels hashtable */
	session->channels = ht_new( 128, &channel_hash_fn, &channel_match_fn, &irc_channel_delete );
	CHECK_PTR_RET( session->channels, FALSE );

	/* create the handlers hashtable */
	session->handlers = ht_new( 8, &handler_hash_fn, &handler_match_fn, &handler_delete_fn );
	CHECK_PTR_RET( session->handlers, FALSE );

	/* store the handler context */
	session->user_data = user_data;

	/* register handlers */
	CHECK_RET( IRC_OK == SET_HANDLER( PING,					HANDLER_FIRST ), FALSE );
	CHECK_RET( IRC_OK == SET_HANDLER( RPL_WELCOME,			HANDLER_FIRST ), FALSE );
	CHECK_RET( IRC_OK == SET_HANDLER( RPL_MYINFO,			HANDLER_FIRST ), FALSE );
	CHECK_RET( IRC_OK == SET_HANDLER( MODE,					HANDLER_FIRST ), FALSE );
	CHECK_RET( IRC_OK == SET_HANDLER( ANYCMD,				HANDLER_LAST  ), FALSE );
	
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
								   irc_command_t const cmd,
								   event_handler_fn event_handler,
								   int const priority )
{
	int ret = FALSE;
	ht_itr_t itr;
	pair_t * p = NULL;
	bt_t * handler_list = NULL;

	CHECK_PTR_RET( session, IRC_BADPARAM );
	CHECK_PTR_RET( session->handlers, IRC_BADPARAM );
	CHECK_RET( IS_VALID_COMMAND( cmd ), IRC_BADPARAM );
	CHECK_PTR_RET( event_handler, IRC_BADPARAM );

	/* look up the btree associated with the specified event name */
	p = pair_new( (void*)cmd, NULL );
	itr = ht_find( session->handlers, (void*)p );
	pair_delete( p );
	p = ((pair_t*)ht_get( session->handlers, itr ));
	handler_list = p ? pair_second( p ) : NULL;

	if ( handler_list == NULL )
	{
		/* create a new btree to store the handlers in priority order */
		handler_list = bt_new( 1, &int_less, NULL, NULL );
		CHECK_PTR_RET( handler_list, IRC_ERR );

		/* add the new handler pointer at the specified priority */
		ret = bt_add( handler_list, (void*)priority, (void*)event_handler );
		CHECK_RET( ret, IRC_ERR );

		/* add the btree to the handlers hashtable under the command */
		ret = ht_insert( session->handlers, pair_new( (void*)cmd, (void*)handler_list ) );
		CHECK_RET( ret, IRC_ERR );
	}
	else
	{
		/* add the new handler pointer at the specified priority */
		ret = bt_add( handler_list, (void*)priority, (void*)event_handler );
		CHECK_RET( ret, IRC_ERR );
	}

	if ( bt_find( handler_list, (void*)priority ) != (void*)event_handler )
	{
		WARN( "adding event handler to event handler list failed!\n" );
		return IRC_ERR;
	}

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
/*************************************************/
/* these are the session specific event handlers */
/*************************************************/
/*************************************************/


/* this gets called when we receive a PING message from the server */
static HANDLER_FN( PING )
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

	return IRC_DONE;
}

/* this gets called when we receive a RPL_WELCOME message from the server */
static HANDLER_FN( RPL_WELCOME )
{
	int8_t const * dest;
	irc_msg_t * pong = NULL;

	CHECK_RET( (msg->cmd == RPL_WELCOME), IRC_BADPARAM );

	/* get a pointer to the last part of the PING message */
	dest = (msg->trailing != NULL) ? msg->trailing : msg->parameters[msg->num_params-1];
	DEBUG("received RPL_WELCOME from %s\n", dest);

	/* we have a registered connection to the server, we're now active */
	session->state = IRC_SESSION_ACTIVE;

	/* call the irc session connected event callback */
	irc_session_call_handler( session, NULL, SESSION_CONNECTED );
	
	return IRC_DONE;
}

/* this gets called when we receive a RPL_MYINFO message from the server */
static HANDLER_FN( RPL_MYINFO )
{
	int8_t const * dest;
	irc_msg_t * pong = NULL;

	CHECK_RET( (msg->cmd == RPL_MYINFO), IRC_BADPARAM );

	switch( msg->num_params )
	{
		case 9: /* KineIRCd */

			/* server modes that take a parameter */
			irc_session_set( session, 
							 SERVER_MODES_PARAM,
							 strdup( msg->parameters[8] ) );
			check_smodes( msg->parameters[8] );

			/* server modes */
			irc_session_set( session, 
							 SERVER_MODES,
							 strdup( msg->parameters[7] ) );
			check_smodes( msg->parameters[7] );

			/* user modes that take a parameter */
			irc_session_set( session, 
							 USER_MODES_PARAM,
							 strdup( msg->parameters[6] ) );
			check_umodes( msg->parameters[6] );

		case 6: /* ircd */

			/* parse the cmodes with a parameter */
			irc_session_set( session, 
							 CHANNEL_MODES_PARAM,
							 strdup( msg->parameters[5] ) );
			check_cmodes( msg->parameters[5] );


		case 5: /* RFC2812 */

			/* channel modes */
			irc_session_set( session, 
							 CHANNEL_MODES,
							 strdup( msg->parameters[4] ) );
			check_cmodes( msg->parameters[4] );

			/* user modes */
			irc_session_set( session, 
							 USER_MODES,
							 strdup( msg->parameters[3] ) );
			check_umodes( msg->parameters[3] );

			/* store version */
			irc_session_set( session,
							 SERVER_VERSION,
							 strdup( msg->parameters[2] ) );
	}

	return IRC_DONE;
}

/* this handles MODE commands from the server */
static HANDLER_FN( MODE )
{
	CHECK_RET( (msg->cmd == MODE), IRC_BADPARAM );

	/* chain to the next handler */
	return IRC_OK;
}

/* this is the catch-all handler that logs all inbound messages */
static HANDLER_FN( ANYCMD )
{
	/* log it */
	irc_msg_log( msg );	

	/* chain to the next handler */
	return IRC_OK;
}

#ifdef UNIT_TESTING

#include <CUnit/Basic.h>

void test_session_private_functions( void )
{
}

#endif

