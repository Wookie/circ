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

#define DEBUG_ON

#include <cutil/debug.h>
#include <cutil/macros.h>
#include <cutil/list.h>

#include "commands.h"
#include "msg.h"
#include "session.h"
#include "event_cb.h"
#include "channel.h"

struct irc_channel_s
{
    int         joining;        /* fully joined? */
    int         parting;        /* fully pared? */
    uint8_t*    name;           /* name of the channel */
    uint8_t*    pass;           /* the channel password */
    uint8_t*    topic;          /* channel topic */
    uint8_t*    part_msg;       /* part message */
    /*int32_t     mode[MODE_WORDS];*//* mode flags */
    list_t*     clients;        /* list of clients in the channel */
    list_t*     join_msgs;      /* list of join messages */
};

/* forward declare the callback functions */
static HANDLER_FN( channel, JOIN );
static HANDLER_FN( channel, PART );
static HANDLER_FN( channel, KICK );
static HANDLER_FN( channel, QUIT );
static HANDLER_FN( channel, RPL_TOPIC );
static HANDLER_FN( channel, RPL_NAMREPLY );
static HANDLER_FN( channel, RPL_ENDOFNAMES );

irc_channel_t * irc_channel_new( uint8_t const * const name, 
                                 uint8_t const * const pass,
                                 uint8_t const * const part_msg )
{
    irc_channel_t * ch = NULL;
    CHECK_PTR_RET( name, NULL );
    
    ch = (irc_channel_t*)CALLOC( 1, sizeof(irc_channel_t) );
    CHECK_PTR_RET( ch, NULL );

    /* store the name */
    ch->name = STRDUP( name );
    CHECK_PTR_GOTO( ch->name, irc_channel_new_fail );

    /* store the channel password */
    if ( pass != NULL )
    {
        ch->pass = STRDUP( pass );
        CHECK_PTR_GOTO( ch->pass, irc_channel_new_fail );
    }

    /* store the part message */
    if ( part_msg != NULL )
    {
        ch->part_msg = STRDUP( part_msg );
        CHECK_PTR_GOTO( ch->part_msg, irc_channel_new_fail );
    }

    /* create the client list */
    ch->clients = list_new( 0, FREE );
    CHECK_PTR_GOTO( ch->clients, irc_channel_new_fail );

    return ch;

irc_channel_new_fail:
    irc_channel_delete( ch );
    return NULL;
}

void irc_channel_delete( void * c )
{
    irc_channel_t * ch = (irc_channel_t*)c;
    CHECK_PTR( ch );

    if ( ch->name != NULL )
        FREE( ch->name );

    if ( ch->pass != NULL )
        FREE( ch->pass );

    if ( ch->part_msg != NULL )
        FREE( ch->part_msg );

    if ( ch->clients != NULL )
        list_delete( (void*)ch->clients );

    FREE( ch );
}

uint8_t * irc_channel_get_name( irc_channel_t * const c )
{
    CHECK_PTR_RET( c, NULL );
    return c->name;
}

uint8_t * irc_channe_get_topic( irc_channel_t * const c )
{
    CHECK_PTR_RET( c, NULL );
    return c->topic;
}

irc_ret_t irc_channel_join( irc_channel_t * const channel, 
                            irc_session_t * const session )
{
    irc_msg_t * join = NULL;
    irc_event_cb_t * join_cb = NULL;
    irc_event_cb_t * part_cb = NULL;
    irc_event_cb_t * kick_cb = NULL;
    irc_event_cb_t * quit_cb = NULL;
    irc_event_cb_t * rpl_topic_cb = NULL;
    irc_event_cb_t * rpl_namreply_cb = NULL;
    irc_event_cb_t * rpl_endofnames_cb = NULL;

    CHECK_PTR_RET( channel, IRC_BADPARAM );
    CHECK_PTR_RET( session, IRC_BADPARAM );
    CHECK_RET( channel->joining == FALSE, IRC_BADPARAM );

    /* register JOIN handler */
    join_cb = NEW_HANDLER( JOIN, session, channel );
    CHECK_RET( (IRC_OK == irc_session_set_handler( session, join_cb )), FALSE );

    /* register PART handler */
    part_cb = NEW_HANDLER( PART, session, channel );
    CHECK_RET( (IRC_OK == irc_session_set_handler( session, part_cb )), FALSE );

    /* register KICK handler */
    kick_cb = NEW_HANDLER( KICK, session, channel );
    CHECK_RET( (IRC_OK == irc_session_set_handler( session, kick_cb )), FALSE );

    /* register QUIT handler */
    quit_cb = NEW_HANDLER( QUIT, session, channel );
    CHECK_RET( (IRC_OK == irc_session_set_handler( session, quit_cb )), FALSE );

    /* register RPL_TOPIC handler */
    rpl_topic_cb = NEW_HANDLER( RPL_TOPIC, session, channel );
    CHECK_RET( (IRC_OK == irc_session_set_handler( session, rpl_topic_cb )), FALSE );

    /* register RPL_NAMREPLY handler */
    rpl_namreply_cb = NEW_HANDLER( RPL_NAMREPLY, session, channel );
    CHECK_RET( (IRC_OK == irc_session_set_handler( session, rpl_namreply_cb )), FALSE );

    /* register RPL_ENDOFNAMES handler */
    rpl_endofnames_cb = NEW_HANDLER( RPL_ENDOFNAMES, session, channel );
    CHECK_RET( (IRC_OK == irc_session_set_handler( session, rpl_endofnames_cb )), FALSE );

    /* set the joining flag to TRUE */
    channel->joining = TRUE;

    /* send the JOIN command */
    join = irc_msg_new();
    if ( channel->pass != NULL )
    {
        irc_msg_set_all( join, JOIN, NULL, 2, channel->name, channel->pass );
    }
    else
    {
        irc_msg_set_all( join, JOIN, NULL, 1, channel->name );
    }

    /* send the JOIN command */
    irc_session_send_msg( session, join );

    return IRC_OK;
}

irc_ret_t irc_channel_part( irc_channel_t * const c, irc_session_t * const session )
{
    irc_msg_t * part = NULL;

    CHECK_PTR_RET( c, IRC_BADPARAM );
    CHECK_PTR_RET( session, IRC_BADPARAM );
    CHECK_RET( c->parting == FALSE, IRC_BADPARAM );

    /* set the parting flag to be true */
    c->parting = TRUE;

    /* send the PART command */
    part = irc_msg_new();
    irc_msg_set_all( part, PART, NULL, 1, c->name );
    if ( c->part_msg != NULL )
    {
        irc_msg_set_trailing( part, c->part_msg );
    }

    /* send the PART command */
    irc_session_send_msg( session, part );

    return IRC_OK;
}

/********** handler callbacks **********/
static HANDLER_FN( channel, JOIN )
{
    irc_channel_t * chan = (irc_channel_t *)user_data;

    CHECK_PTR_RET( session, IRC_BADPARAM );
    CHECK_PTR_RET( msg, IRC_BADPARAM );
    CHECK_PTR_RET( user_data, IRC_BADPARAM );

    /* used to track users joining the channel */

    if ( chan->joining )
    {
        DEBUG( "successfully joined channel: %s\n", chan->name );
        chan->joining = FALSE;
        return IRC_OK;
    }

    /* somebody else joined so add them to the list of clients */

    return IRC_OK;
}

static HANDLER_FN( channel, PART )
{
    irc_channel_t * chan = (irc_channel_t *)user_data;

    CHECK_PTR_RET( session, IRC_BADPARAM );
    CHECK_PTR_RET( msg, IRC_BADPARAM );
    CHECK_PTR_RET( user_data, IRC_BADPARAM );

    /* used to track users leaving the channel */

    if ( chan->parting )
    {
        DEBUG( "successfully parted channel: %s\n", chan->name );
        chan->parting = FALSE;

        /* unhook our callbacks */

        return IRC_OK;
    }

    /* somebody else parted so remove them from the list of clients */

    return IRC_OK;
}

static HANDLER_FN( channel, KICK )
{
    irc_channel_t * chan = (irc_channel_t *)user_data;

    CHECK_PTR_RET( session, IRC_BADPARAM );
    CHECK_PTR_RET( msg, IRC_BADPARAM );
    CHECK_PTR_RET( user_data, IRC_BADPARAM );

    /* used to track users being kicked from the channel */
    return IRC_OK;
}

static HANDLER_FN( channel, QUIT )
{
    irc_channel_t * chan = (irc_channel_t *)user_data;

    CHECK_PTR_RET( session, IRC_BADPARAM );
    CHECK_PTR_RET( msg, IRC_BADPARAM );
    CHECK_PTR_RET( user_data, IRC_BADPARAM );

    /* used to track users quitting the server */
    return IRC_OK;
}

static HANDLER_FN( channel, RPL_TOPIC )
{
    irc_channel_t * chan = (irc_channel_t *)user_data;

    CHECK_PTR_RET( session, IRC_BADPARAM );
    CHECK_PTR_RET( msg, IRC_BADPARAM );
    CHECK_PTR_RET( user_data, IRC_BADPARAM );

    /* receive the channel topic */
    if ( chan->topic != NULL )
    {
        FREE( chan->topic );
        chan->topic = NULL;
    }

    if ( irc_msg_get_trailing( msg ) != NULL )
    {
        /* copy the topic from the trailing part of the message */
        chan->topic = strdup(irc_msg_get_trailing( msg ));
    }

    return IRC_OK;
}

static HANDLER_FN( channel, RPL_NAMREPLY )
{
    uint8_t * nick = NULL;
    uint8_t * s = NULL;
    uint8_t * f = NULL;
    ht_itr_t itr;
    irc_channel_t * chan = (irc_channel_t *)user_data;
    
    CHECK_PTR_RET( session, IRC_BADPARAM );
    CHECK_PTR_RET( msg, IRC_BADPARAM );
    CHECK_PTR_RET( user_data, IRC_BADPARAM );
    CHECK_PTR_RET( irc_msg_get_trailing( msg ), IRC_ERR );

    /* this receives the list of names of people already in the
     * channel when we join it */
    s = f = irc_msg_get_trailing( msg );
    while ( *f != '\0' )
    {
        if ( *f == ' ' )
        {
            /* @ == moderator, + == can speak in moderated channel */
            if ( (*s == '@') || (*s == '+') )
            {
                s++;
            }
            strncpy( nick, s, (f - s) );
            f++;
            s = f;
            list_push_tail( chan->clients, nick );
        }
        else
        {
            f++;
        }
    }

    return IRC_OK;
}

static HANDLER_FN( channel, RPL_ENDOFNAMES )
{
    ht_itr_t itr;
    list_itr_t nitr, nend;
    uint8_t * name = NULL;
    irc_channel_t * chan = NULL;
    chan = (irc_channel_t*)user_data;
    CHECK_PTR_RET( chan, IRC_ERR );

    /* the end of the names list */

    nitr = list_itr_begin( chan->clients );
    nend = list_itr_end( chan->clients );
    DEBUG( "Channel %s users:\n", chan->name );
    for ( ; nitr != nend; nitr = list_itr_next( chan->clients, nitr ) )
    {
        name = (uint8_t*)list_get_head( chan->clients );
        DEBUG( "\t%s\n", name );
    }

    return IRC_OK;
}



