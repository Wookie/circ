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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

#include <cutil/debug.h>
#include <cutil/macros.h>

/* the event names for 100 IRC msg codes */
int8_t const * const irc_events_100[] =
{
	NULL,
	T("welcome"),		/* 001 */
	T("yourhost"),		/* 002 */
	T("created"),		/* 003 */
	T("myinfo"),		/* 004 */
	T("featurelist")	/* 005 */
};

/* the event names for 200 IRC msg codes */
int8_t const * const irc_events_200[] =
{
	T("tracelink"),			/* 200 */
	T("traceconnecting"),	/* 201 */
	T("tracehandshake"),	/* 202 */
	T("traceunknown"),		/* 203 */
	T("traceoperator"),		/* 204 */
	T("traceuser"),			/* 205 */
	T("traceserver"),		/* 206 */
	T("traceservice"),		/* 207 */
	T("tracenewtype"),		/* 208 */
	T("traceclass"),		/* 209 */
	T("tracereconnect"),	/* 210 */
	T("statslinkinfo"),		/* 211 */
	T("statscommands"),		/* 212 */
	T("statscline"),		/* 213 */
	T("statsnline"),		/* 214 */
	T("statsiline"),		/* 215 */
	T("statskline"),		/* 216 */
	T("statsqline"),		/* 217 */
	T("statsyline"),		/* 218 */
	T("endofstats"),		/* 219 */
	NULL,
	T("umodeis"),			/* 221 */
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	T("serviceinfo"),		/* 231 */
	T("endofservices"),		/* 232 */
	T("service"),			/* 233 */
	T("servlist"),			/* 234 */
	T("servlistend"),		/* 235 */
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	T("statslline"),		/* 241 */
	T("statsuptime"),		/* 242 */
	T("statsonline"),		/* 243 */
	T("statshline"),		/* 244 */
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	T("luserconns"),		/* 250 */
	T("luserclient"),		/* 251 */
	T("luserop"),			/* 252 */
	T("luserunknown"),		/* 253 */
	T("luserchannels"),		/* 254 */
	T("luserme"),			/* 255 */
	T("adminme"),			/* 256 */
	T("adminloc1"),			/* 257 */
	T("adminloc2"),			/* 258 */
	T("adminemail"),		/* 259 */
	NULL,
	T("tracelog"),			/* 261 */
	T("endoftrace"),		/* 262 */
	T("tryagain"),			/* 263 */
	NULL,
	T("n_local"),			/* 265 */
	T("n_global")			/* 266 */
};
 
/* the event names for 300 IRC msg codes */
int8_t const * const irc_events_300[] =
{
    T("none"),				/* 300 */
    T("away"),				/* 301 */
    T("userhost"),			/* 302 */
    T("ison"),				/* 303 */
	NULL,
    T("unaway"),			/* 305 */
    T("nowaway"),			/* 306 */
	NULL,
	NULL,
	NULL,
	NULL,
    T("whoisuser"),			/* 311 */
    T("whoisserver"),		/* 312 */
    T("whoisoperator"),		/* 313 */
    T("whowasuser"),		/* 314 */
    T("endofwho"),			/* 315 */
    T("whoischanop"),		/* 316 */
    T("whoisidle"),			/* 317 */
    T("endofwhois"),		/* 318 */
    T("whoischannels"),		/* 319 */
	NULL,
    T("liststart"),			/* 321 */
    T("list"),				/* 322 */
    T("listend"),			/* 323 */
    T("channelmodeis"),		/* 324 */
	NULL,
	NULL,
	NULL,
	NULL,
    T("channelcreate"),		/* 329 */
	NULL,
    T("notopic"),			/* 331 */
    T("currenttopic"),		/* 332 */
    T("topicinfo"),			/* 333 */
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
    T("inviting"),			/* 341 */
    T("summoning"),			/* 342 */
	NULL,
	NULL,
	NULL,
    T("invitelist"),		/* 346 */
    T("endofinvitelist"),	/* 347 */
    T("exceptlist"),		/* 348 */
    T("endofexceptlist"),	/* 349 */
	NULL,
    T("version"),			/* 351 */
    T("whoreply"),			/* 352 */
    T("namreply"),			/* 353 */
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
    T("killdone"),			/* 361 */
    T("closing"),			/* 362 */
    T("closeend"),			/* 363 */
    T("links"),				/* 364 */
    T("endoflinks"),		/* 365 */
    T("endofnames"),		/* 366 */
    T("banlist"),			/* 367 */
    T("endofbanlist"),		/* 368 */
    T("endofwhowas"),		/* 369 */
	NULL,
    T("info"),				/* 371 */
    T("motd"),				/* 372 */
    T("infostart"),			/* 373 */
    T("endofinfo"),			/* 374 */
    T("motdstart"),			/* 375 */
    T("endofmotd"),			/* 376 */
    T("motd2"),				/* 377 */
	NULL,
	NULL,
	NULL,
    T("youreoper"),			/* 381 */
    T("rehashing"),			/* 382 */
	NULL,
    T("myportis"),			/* 384 */
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
    T("time"),				/* 391 */
    T("usersstart"),		/* 392 */
    T("users"),				/* 393 */
    T("endofusers"),		/* 394 */
    T("nousers")			/* 395 */
};

/* the event names for 400 IRC msg codes */
int8_t const * const irc_events_400[] =
{
    T("nosuchnick"),		/* 401 */
    T("nosuchserver"),		/* 402 */
    T("nosuchchannel"),		/* 403 */
    T("cannotsendtochan"),	/* 404 */
    T("toomanychannels"),	/* 405 */
    T("wasnosuchnick"),		/* 406 */
    T("toomanytargets"),	/* 407 */
    T("noorigin"),			/* 409 */
	NULL,
    T("norecipient"),		/* 411 */
    T("notexttosend"),		/* 412 */
    T("notoplevel"),		/* 413 */
    T("wildtoplevel"),		/* 414 */
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
    T("unknowncommand"),	/* 421 */
    T("nomotd"),			/* 422 */
    T("noadmininfo"),		/* 423 */
    T("fileerror"),			/* 424 */
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
    T("nonicknamegiven"),	/* 431 */
    T("erroneusnickname"),	/* 432 Thiss iz how its speld in thee RFC. */
    T("nicknameinuse"),		/* 433 */
	NULL,
	NULL,
    T("nickcollision"),		/* 436 */
    T("unavailresource"),	/* 437 */
	NULL,
	NULL,
	NULL,
    T("usernotinchannel"),	/* 441 */
    T("notonchannel"),		/* 442 */
    T("useronchannel"),		/* 443 */
    T("nologin"),			/* 444 */
    T("summondisabled"),	/* 445 */
    T("usersdisabled"),		/* 446 */
	NULL,
	NULL,
	NULL,
	NULL,
    T("notregistered"),		/* 451 */
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
    T("needmoreparams"),	/* 461 */
    T("alreadyregistered"),	/* 462 */
    T("nopermforhost"),		/* 463 */
    T("passwdmismatch"),	/* 464 */
    T("yourebannedcreep"),	/* 465 */
    T("youwillbebanned"),	/* 466 */
    T("keyset"),			/* 467 */
	NULL,
	NULL,
	NULL,
    T("channelisfull"),		/* 471 */
    T("unknownmode"),		/* 472 */
    T("inviteonlychan"),	/* 473 */
    T("bannedfromchan"),	/* 474 */
    T("badchannelkey"),		/* 475 */
    T("badchanmask"),		/* 476 */
    T("nochanmodes"),		/* 477 */
    T("banlistfull"),		/* 478 */
	NULL,
	NULL,
    T("noprivileges"),		/* 481 */
    T("chanoprivsneeded"),	/* 482 */
    T("cantkillserver"),	/* 483 */
    T("restricted"),		/* 484 */
    T("uniqopprivsneeded"),	/* 485 */
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
    T("nooperhost"),		/* 491 */
    T("noservicehost"),		/* 492 */
};

/* the event names for 500 IRC msg codes */
int8_t const * const irc_events_500[] =
{
	NULL,
	T("umodeunknownflag"),	/* 501 */
	T("usersdontmatch"),	/* 502 */
};

/* the event names for IRC commands */
int8_t const * const irc_command_events[] =
{
    /* RFC 2812, Section 3.1 -- Connection Registration */
    NULL,			/* PASS */
    NULL,			/* NICK */
    NULL,			/* USER */
    NULL,			/* OPER */
    T("mode"),		/* MODE */
    NULL,			/* SERVICE */
    T("quit"),		/* QUIT */
    T("squit"),		/* SQUIT */

    /* RFC 2812, Section 3.2 -- Channel Operations */
    T("join"),		/* JOIN */
    T("part"),		/* PART */
    /* MODE */  /* also a connection registration command */
    NULL,			/* TOPIC */
    NULL,			/* NAMES */
    NULL,			/* LIST */
    T("invite"),		/* INVITE */
    T("kick"),		/* KICK */
    
    /* RFC 2812, Section 3.3 -- Sending Messages */
    T("privmsg"),	/* PRIVMSG */
    T("notice"),		/* NOTICE */
    
    /* RFC 2812, Section 3.4 -- Server Queries and Commands */
    NULL,			/* MOTD */
    NULL,			/* LUSERS */
    NULL,			/* VERSION */
    NULL,			/* STATS */
    NULL,			/* LINKS */
    NULL,			/* TIME */
    NULL,			/* CONNECT */
    NULL,			/* TRACE */
    NULL,			/* ADMIN */
    NULL,			/* INFO */
        
    /* RFC 2812, Section 3.5 -- Service Query and Commands */
    NULL,			/* SERVLIST */
    NULL,			/* SQUERY */
    
    /* RFC 2812, Section 3.6 -- User Based Queries */
    NULL,			/* WHO */
    NULL,			/* WHOIS */
    NULL,			/* WHOWAS */
    
    /* RFC 2812, Section 3.7 -- Misc Messages */
    T("kill"),		/* KILL */
    T("ping"),		/* PING */
    T("pong"),		/* PONG */
    T("error"),		/* ERROR */
    
    /* RFC 2812, Section 4 -- Optional Features */
    T("away"),		/* AWAY */
    NULL,			/* REHASH */
    NULL,			/* DIE */
    NULL,			/* RESTART */
    NULL,			/* SUMMON */
    NULL,			/* USERS */
    T("wallops"),	/* WALLOPS */
    NULL,			/* USERHOST */
    NULL			/* ISON */
};

int8_t const * const irc_session_events[] =
{
	T("connected"),		/* when the session is established */
	T("disconnected")	/* when the session is torn down */
};


#define ARRAY_SIZE( x ) (sizeof(x) / sizeof(x[0]))


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

int main(int argc, char** argv)
{
	/* iterate over the event name lists and output event name/hash tuples */
	int i;

	/* 100's */
	printf( "/* the event names for 100 IRC msg codes */\n" );
	printf( "event_name_t const irc_events_h_100[] =\n" );
	printf( "{\n" );
	for ( i = 0; i < ARRAY_SIZE(irc_events_100); i++ )
	{
		if ( irc_events_100[i] != NULL )
		{
			printf( "\t{ T(\"%s\"), 0x%08x },\n", irc_events_100[i], fnv_key_hash(irc_events_100[i]) );
		}
		else
		{
			printf( "\t{ NULL, 0 },\n" );
		}
	}
	printf( "};\n\n\n" );

	/* 200's */
	printf( "/* the event names for 200 IRC msg codes */\n" );
	printf( "event_name_t const irc_events_h_200[] =\n" );
	printf( "{\n" );
	for ( i = 0; i < ARRAY_SIZE(irc_events_200); i++ )
	{
		if ( irc_events_200[i] != NULL )
		{
			printf( "\t{ T(\"%s\"), 0x%08x },\n", irc_events_200[i], fnv_key_hash(irc_events_200[i]) );
		}
		else
		{
			printf( "\t{ NULL, 0 },\n" );
		}
	}
	printf( "};\n\n\n" );

	/* 300's */
	printf( "/* the event names for 300 IRC msg codes */\n" );
	printf( "event_name_t const irc_events_h_300[] =\n" );
	printf( "{\n" );
	for ( i = 0; i < ARRAY_SIZE(irc_events_300); i++ )
	{
		if ( irc_events_300[i] != NULL )
		{
			printf( "\t{ T(\"%s\"), 0x%08x },\n", irc_events_300[i], fnv_key_hash(irc_events_300[i]) );
		}
		else
		{
			printf( "\t{ NULL, 0 },\n" );
		}
	}
	printf( "};\n\n\n" );

	/* 400's */
	printf( "/* the event names for 400 IRC msg codes */\n" );
	printf( "event_name_t const irc_events_h_400[] =\n" );
	printf( "{\n" );
	for ( i = 0; i < ARRAY_SIZE(irc_events_400); i++ )
	{
		if ( irc_events_400[i] != NULL )
		{
			printf( "\t{ T(\"%s\"), 0x%08x },\n", irc_events_400[i], fnv_key_hash(irc_events_400[i]) );
		}
		else
		{
			printf( "\t{ NULL, 0 },\n" );
		}
	}
	printf( "};\n\n\n" );

	/* 500's */
	printf( "/* the event names for 500 IRC msg codes */\n" );
	printf( "event_name_t const irc_events_h_500[] =\n" );
	printf( "{\n" );
	for ( i = 0; i < ARRAY_SIZE(irc_events_500); i++ )
	{
		if ( irc_events_500[i] != NULL )
		{
			printf( "\t{ T(\"%s\"), 0x%08x },\n", irc_events_500[i], fnv_key_hash(irc_events_500[i]) );
		}
		else
		{
			printf( "\t{ NULL, 0 },\n" );
		}
	}
	printf( "};\n\n\n" );

	/* commands */
	printf( "/* the event names for IRC commands msg codes */\n" );
	printf( "event_name_t const irc_command_events[] =\n" );
	printf( "{\n" );
	for ( i = 0; i < ARRAY_SIZE(irc_command_events); i++ )
	{
		if ( irc_command_events[i] != NULL )
		{
			printf( "\t{ T(\"%s\"), 0x%08x },\n", irc_command_events[i], fnv_key_hash(irc_command_events[i]) );
		}
		else
		{
			printf( "\t{ NULL, 0 },\n" );
		}
	}
	printf( "};\n\n\n" );

	/* session */
	printf( "/* the event names for IRC session events */\n" );
	printf( "event_name_t const irc_session_events[] =\n" );
	printf( "{\n" );
	for ( i = 0; i < ARRAY_SIZE(irc_session_events); i++ )
	{
		if ( irc_session_events[i] != NULL )
		{
			printf( "\t{ T(\"%s\"), 0x%08x },\n", irc_session_events[i], fnv_key_hash(irc_session_events[i]) );
		}
		else
		{
			printf( "\t{ NULL, 0 },\n" );
		}
	}
	printf( "};\n\n\n" );


	return 0;
}


