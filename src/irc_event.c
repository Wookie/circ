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
#include <stdint.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#include <cutil/debug.h>
#include <cutil/macros.h>

#include "irc_commands.h"
#include "irc_event.h"

/* the event names for 000 IRC msg codes */
event_name_t const irc_reply_events_000[] =
{
	{ NULL,	0 },
	{ T("welcome"),			0x905c7ca7 },	/* 001 */
	{ T("yourhost"),		0x4778f70a },	/* 002 */
	{ T("created"),			0xd604f2a3 },	/* 003 */
	{ T("myinfo"),			0xe521d95f },	/* 004 */
	{ T("featurelist"),		0x920381c9 },	/* 005 */
};

/* no IRC codes in the 100 range */

/* the event names for 200 IRC msg codes */
event_name_t const irc_reply_events_200[] =
{
	{ T("tracelink"),		0xad392f44 },	/* 200 */
	{ T("traceconnecting"), 0xc7d3013a },	/* 201 */
	{ T("tracehandshake"),	0x1344044f },	/* 202 */
	{ T("traceunknown"),	0x0a8df12a },	/* 203 */
	{ T("traceoperator"),	0xf720d964 },	/* 204 */
	{ T("traceuser"),		0x97f44365 },	/* 205 */
	{ T("traceserver"),		0xe010d6a5 },	/* 206 */
	{ T("traceservice"),	0x6663dbd5 },	/* 207 */
	{ T("tracenewtype"),	0xc99f2b7e },	/* 208 */
	{ T("traceclass"),		0xbb33b94c },	/* 209 */
	{ T("tracereconnect"),	0x0a75036b },	/* 210 */
	{ T("statslinkinfo"),	0xaa8d0306 },	/* 211 */
	{ T("statscommands"),	0xcd695a20 },	/* 212 */
	{ T("statscline"),		0xa50b0ab3 },	/* 213 */
	{ T("statsnline"),		0xb31c0e22 },	/* 214 */
	{ T("statsiline"),		0x60230739 },	/* 215 */
	{ T("statskline"),		0xaa0626cb },	/* 216 */
	{ T("statsqline"),		0xe2805411 },	/* 217 */
	{ T("statsyline"),		0x2a05d5e9 },	/* 218 */
	{ T("endofstats"),		0xb8a7e8ac },	/* 219 */
	{ NULL, 0 },
	{ T("umodeis"),			0xa3f361d7 },	/* 221 */
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ T("serviceinfo"),		0x837eae9e },	/* 231 */
	{ T("endofservices"),	0x84bd119f },	/* 232 */
	{ T("service"),			0xf4fac676 },	/* 233 */
	{ T("servlist"),		0xc13b02bd },	/* 234 */
	{ T("servlistend"),		0x7fe3481c },	/* 235 */
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ T("statslline"),		0x86b902c8 },	/* 241 */
	{ T("statsuptime"),		0x7ab8406a },	/* 242 */
	{ T("statsonline"),		0x8816ca3b },	/* 243 */
	{ T("statshline"),		0xc4b5d52c },	/* 244 */
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ T("luserconns"),		0xd52ec5ff },	/* 250 */
	{ T("luserclient"),		0xa79d5947 },	/* 251 */
	{ T("luserop"),			0xf9b4614b },	/* 252 */
	{ T("luserunknown"),	0x55dd26b4 },	/* 253 */
	{ T("luserchannels"),	0xb4ba5682 },	/* 254 */
	{ T("luserme"),			0xfbb46404 },	/* 255 */
	{ T("adminme"),			0x63715ddc },	/* 256 */
	{ T("adminloc1"),		0x920b0829 },	/* 257 */
	{ T("adminloc2"),		0x920b082a },	/* 258 */
	{ T("adminemail"),		0xfd7f2ffe },	/* 259 */
	{ NULL, 0 },
	{ T("tracelog"),		0x93cc16ea },	/* 261 */
	{ T("endoftrace"),		0x59280822 },	/* 262 */
	{ T("tryagain"),		0xa5f819a4 },	/* 263 */
	{ NULL, 0 },
	{ T("n_local"),			0xf0a83185 },	/* 265 */
	{ T("n_global"),		0x790cfb59 },	/* 266 */
};


/* the event names for 300 IRC msg codes */
event_name_t const irc_reply_events_300[] =
{
	{ T("none"),			0x2ca33bdb },	/* 300 */
	{ T("away"),			0xd3c2c5fb },	/* 301 */
	{ T("userhost"),		0xe9f6d30a },	/* 302 */
	{ T("ison"),			0x4ed3034a },	/* 303 */
	{ NULL, 0 },
	{ T("unaway"),			0x862bcc5e },	/* 305 */
	{ T("nowaway"),			0xed486d2d },	/* 306 */
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ T("whoisuser"),		0x612bb09e },	/* 311 */
	{ T("whoisserver"),		0xd58c87fe },	/* 312 */
	{ T("whoisoperator"),	0x8490fba7 },	/* 313 */
	{ T("whowasuser"),		0x0e031e7f },	/* 314 */
	{ T("endofwho"),		0x9b53e75d },	/* 315 */
	{ T("whoischanop"),		0x1d28814a },	/* 316 */
	{ T("whoisidle"),		0x05eca4f9 },	/* 317 */
	{ T("endofwhois"),		0xf565ab79 },	/* 318 */
	{ T("whoischannels"),	0x3e31090f },	/* 319 */
	{ NULL, 0 },
	{ T("liststart"),		0x4b044a5f },	/* 321 */
	{ T("list"),			0x0d20b3dd },	/* 322 */
	{ T("listend"),			0xf7ec22bc },	/* 323 */
	{ T("channelmodeis"),	0xd62ffcd7 },	/* 324 */
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ T("channelcreate"),	0x3072f2de },	/* 329 */
	{ NULL, 0 },
	{ T("notopic"),			0xdcc62609 },	/* 331 */
	{ T("currenttopic"),	0x9b710245 },	/* 332 */
	{ T("topicinfo"),		0x4953017e },	/* 333 */
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ T("inviting"),		0x692308cf },	/* 341 */
	{ T("summoning"),		0x096badc8 },	/* 342 */
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ T("invitelist"),		0xbb4e4d72 },	/* 346 */
	{ T("endofinvitelist"), 0x80de5cd0 },	/* 347 */
	{ T("exceptlist"),		0xcd9ba426 },	/* 348 */
	{ T("endofexceptlist"), 0xfa4cbb30 },	/* 349 */
	{ NULL, 0 },
	{ T("version"),			0x7e51c1bb },	/* 351 */
	{ T("whoreply"),		0x90cc6405 },	/* 352 */
	{ T("namreply"),		0xb9c7b419 },	/* 353 */
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ T("killdone"),		0x4c0066d9 },	/* 361 */
	{ T("closing"),			0xaea7abca },	/* 362 */
	{ T("closeend"),		0x0066db2e },	/* 363 */
	{ T("links"),			0x6c6e2e00 },	/* 364 */
	{ T("endoflinks"),		0xe40ea8a2 },	/* 365 */
	{ T("endofnames"),		0xe5a0acdd },	/* 366 */
	{ T("banlist"),			0x16141474 },	/* 367 */
	{ T("endofbanlist"),	0xeea2871e },	/* 368 */
	{ T("endofwhowas"),		0xc61169f0 },	/* 369 */
	{ NULL, 0 },
	{ T("info"),			0x45c62969 },	/* 371 */
	{ T("motd"),			0xb57b5899 },	/* 372 */
	{ T("infostart"),		0xbc331353 },	/* 373 */
	{ T("endofinfo"),		0x5ddaf48f },	/* 374 */
	{ T("motdstart"),		0x4545fba3 },	/* 375 */
	{ T("endofmotd"),		0xc9406ccf },	/* 376 */
	{ T("motd2"),			0x4a2c78e9 },	/* 377 */
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ T("youreoper"),		0x4111abd1 },	/* 381 */
	{ T("rehashing"),		0xa9600562 },	/* 382 */
	{ NULL, 0 },
	{ T("myportis"),		0x77e6b6f6 },	/* 384 */
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ T("time"),			0x9e3669da },	/* 391 */
	{ T("usersstart"),		0xbe8d270d },	/* 392 */
	{ T("users"),			0x14835dff },	/* 393 */
	{ T("endofusers"),		0x4bfc54a9 },	/* 394 */
	{ T("nousers"),			0x9a5d5914 },	/* 395 */
};


/* the event names for 400 IRC msg codes */
event_name_t const irc_error_events_400[] =
{
	{ NULL, 0 },
	{ T("nosuchnick"),		0x9c6cc270 },	/* 401 */
	{ T("nosuchserver"),	0x22ed2800 },	/* 402 */
	{ T("nosuchchannel"),	0x8e3735ee },	/* 403 */
	{ T("cannotsendtochan"),0x2adbf541 },	/* 404 */
	{ T("toomanychannels"),	0xcf87ff20 },	/* 405 */
	{ T("wasnosuchnick"),	0xa773aae5 },	/* 406 */
	{ T("toomanytargets"),	0xc75796f2 },	/* 407 */
	{ NULL, 0 },
	{ T("noorigin"),		0xb71048da },	/* 409 */
	{ NULL, 0 },
	{ T("norecipient"),		0xaf9bd029 },	/* 411 */
	{ T("notexttosend"),	0xe3f9992c },	/* 412 */
	{ T("notoplevel"),		0xc44d3b6d },	/* 413 */
	{ T("wildtoplevel"),	0x6c688040 },	/* 414 */
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ T("unknowncommand"),	0xe121cd9c },	/* 421 */
	{ T("nomotd"),			0xa83ff78c },	/* 422 */
	{ T("noadmininfo"),		0xd07036c5 },	/* 423 */
	{ T("fileerror"),		0xb8f0b1b7 },	/* 424 */
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ T("nonicknamegiven"), 0xd0506a97 },	/* 431 */
	{ T("erroneusnickname"),0x9fc3230a },	/* 432 */
	{ T("nicknameinuse"),	0x6ff45115 },	/* 433 */
	{ NULL, 0 },
	{ NULL, 0 },
	{ T("nickcollision"),	0xfff9bcd4 },	/* 436 */
	{ T("unavailresource"), 0x3e2ec1e9 },	/* 437 */
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ T("usernotinchannel"),0x603a411b },	/* 441 */
	{ T("notonchannel"),	0x5c0b8730 },	/* 442 */
	{ T("useronchannel"),	0xdcde9adc },	/* 443 */
	{ T("nologin"),			0x9539e9e3 },	/* 444 */
	{ T("summondisabled"),	0x2fb33168 },	/* 445 */
	{ T("usersdisabled"),	0x28fdfbdf },	/* 446 */
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ T("notregistered"),	0x8dc78f50 },	/* 451 */
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ T("needmoreparams"),	0x8906af44 },	/* 461 */
	{ T("alreadyregistered"),0xb96b0577 },	/* 462 */
	{ T("nopermforhost"),	0xd63196d9 },	/* 463 */
	{ T("passwdmismatch"),	0x8f05bd47 },	/* 464 */
	{ T("yourebannedcreep"),0x424e4d3c },	/* 465 */
	{ T("youwillbebanned"), 0xacfcb611 },	/* 466 */
	{ T("keyset"),			0x2f7ec56a },	/* 467 */
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ T("channelisfull"),	0x5f29fe09 },	/* 471 */
	{ T("unknownmode"),		0x93898320 },	/* 472 */
	{ T("inviteonlychan"),	0xcc392934 },	/* 473 */
	{ T("bannedfromchan"),	0x0c0c3375 },	/* 474 */
	{ T("badchannelkey"),	0x6c5988e4 },	/* 475 */
	{ T("badchanmask"),		0x9b60fd06 },	/* 476 */
	{ T("nochanmodes"),		0x8d3cdab4 },	/* 477 */
	{ T("banlistfull"),		0xa012215b },	/* 478 */
	{ NULL, 0 },
	{ NULL, 0 },
	{ T("noprivileges"),	0x1a772dd4 },	/* 481 */
	{ T("chanoprivsneeded"),0x177e5549 },	/* 482 */
	{ T("cantkillserver"),	0x9fe917ca },	/* 483 */
	{ T("restricted"),		0x3d96c542 },	/* 484 */
	{ T("uniqopprivsneeded"),0x9f07dc18 },	/* 485 */
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ T("nooperhost"),		0x9444a9d6 },	/* 491 */
	{ T("noservicehost"),	0x1d19329b },	/* 492 */
};


/* the event names for 500 IRC msg codes */
event_name_t const irc_error_events_500[] =
{
	{ NULL, 0 },
	{ T("umodeunknownflag"),0x40c76d91 },	/* 501 */
	{ T("usersdontmatch"),	0x04f12e25 },	/* 502 */
};

/* the event names for IRC commands */
event_name_t const irc_command_events[] =
{
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ T("mode"), 0xc57b7248 },
	{ NULL, 0 },
	{ T("quit"), 0xea4b2998 },
	{ T("squit"), 0x6e9fa331 },
	{ T("join"), 0xdc402d65 },
	{ T("part"), 0x5ffa86a6 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ T("invite"), 0xb4b1289e },
	{ T("kick"), 0x820c394f },
	{ T("privmsg"), 0x08793e69 },
	{ T("notice"), 0xb1b66d8d },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ T("kill"), 0x790c2a95 },
	{ T("ping"), 0x73e71ef1 },
	{ T("pong"), 0x73e2a10f },
	{ T("error"), 0x70192415 },
	{ T("away"), 0xd3c2c5fb },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ T("wallops"), 0x0b278dd7 },
	{ NULL, 0 },
	{ NULL, 0 },
};


/* the event names for IRC session events */
event_name_t const irc_session_events[] =
{
	{ T("connected"), 0x61201b16 },
	{ T("disconnected"), 0x7f0ec4a4 },
};


/* translate a command into an event name */
int8_t const * irc_event_get_name_from_cmd(irc_command_t const cmd)
{
	int32_t c;
	CHECK_RET(IS_VALID_EVENT(cmd), NULL);

	c = (int32_t)cmd;

	if ( (c > 0) && (c < 100) )
	{
		return irc_reply_events_000[c].name;
	}
	else if ( (c >= 200) && (c < 300) )
	{
		return irc_reply_events_200[c - 200].name;
	}
	else if ( (c >= 300) && (c < 400) )
	{
		return irc_reply_events_300[c - 300].name;
	}
	else if ( (c >= 400) && (c < 500) ) 
	{
		return irc_error_events_400[c - 400].name;
	}
	else if ( (c >= 500) && (c < FIRST_COMMAND) )
	{
		return irc_error_events_500[c - 500].name;
	}
	else if ( (c >= FIRST_COMMAND) && (c < LAST_COMMAND) )
	{
		return irc_command_events[c - FIRST_COMMAND].name;
	}
	else
	{
		return irc_session_events[c - FIRST_SESSION_EVENT].name;
	}

	return NULL;
}

/* translate a command into an event name hash */
uint32_t irc_event_get_hash_from_cmd(irc_command_t const cmd)
{
	int32_t c;
	CHECK_RET(IS_VALID_EVENT(cmd), 0);

	c = (int32_t)cmd;

	if ( (c > 0) && (c < 100) )
	{
		return irc_reply_events_000[c].hash;
	}
	else if ( (c >= 200) && (c < 300) )
	{
		return irc_reply_events_200[c - 200].hash;
	}
	else if ( (c >= 300) && (c < 400) )
	{
		return irc_reply_events_300[c - 300].hash;
	}
	else if ( (c >= 400) && (c < 500) ) 
	{
		return irc_error_events_400[c - 400].hash;
	}
	else if ( (c >= 500) && (c < FIRST_COMMAND) )
	{
		return irc_error_events_500[c - 500].hash;
	}
	else if ( (c >= FIRST_COMMAND) && (c < LAST_COMMAND) )
	{
		return irc_command_events[c - FIRST_COMMAND].hash;
	}
	else
	{
		return irc_session_events[c - FIRST_SESSION_EVENT].hash;
	}
	
	return 0;
}

