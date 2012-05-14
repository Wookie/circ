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
event_name_t const irc_events_h_000[] =
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
event_name_t const irc_events_h_200[] =
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
event_name_t const irc_events_h_300[] =
{
	{ T("none"), 0x2ca33bdb },
	{ T("away"), 0xd3c2c5fb },
	{ T("userhost"), 0xe9f6d30a },
	{ T("ison"), 0x4ed3034a },
	{ NULL, 0 },
	{ T("unaway"), 0x862bcc5e },
	{ T("nowaway"), 0xed486d2d },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ T("whoisuser"), 0x612bb09e },
	{ T("whoisserver"), 0xd58c87fe },
	{ T("whoisoperator"), 0x8490fba7 },
	{ T("whowasuser"), 0x0e031e7f },
	{ T("endofwho"), 0x9b53e75d },
	{ T("whoischanop"), 0x1d28814a },
	{ T("whoisidle"), 0x05eca4f9 },
	{ T("endofwhois"), 0xf565ab79 },
	{ T("whoischannels"), 0x3e31090f },
	{ NULL, 0 },
	{ T("liststart"), 0x4b044a5f },
	{ T("list"), 0x0d20b3dd },
	{ T("listend"), 0xf7ec22bc },
	{ T("channelmodeis"), 0xd62ffcd7 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ T("channelcreate"), 0x3072f2de },
	{ NULL, 0 },
	{ T("notopic"), 0xdcc62609 },
	{ T("currenttopic"), 0x9b710245 },
	{ T("topicinfo"), 0x4953017e },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ T("inviting"), 0x692308cf },
	{ T("summoning"), 0x096badc8 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ T("invitelist"), 0xbb4e4d72 },
	{ T("endofinvitelist"), 0x80de5cd0 },
	{ T("exceptlist"), 0xcd9ba426 },
	{ T("endofexceptlist"), 0xfa4cbb30 },
	{ NULL, 0 },
	{ T("version"), 0x7e51c1bb },
	{ T("whoreply"), 0x90cc6405 },
	{ T("namreply"), 0xb9c7b419 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ T("killdone"), 0x4c0066d9 },
	{ T("closing"), 0xaea7abca },
	{ T("closeend"), 0x0066db2e },
	{ T("links"), 0x6c6e2e00 },
	{ T("endoflinks"), 0xe40ea8a2 },
	{ T("endofnames"), 0xe5a0acdd },
	{ T("banlist"), 0x16141474 },
	{ T("endofbanlist"), 0xeea2871e },
	{ T("endofwhowas"), 0xc61169f0 },
	{ NULL, 0 },
	{ T("info"), 0x45c62969 },
	{ T("motd"), 0xb57b5899 },
	{ T("infostart"), 0xbc331353 },
	{ T("endofinfo"), 0x5ddaf48f },
	{ T("motdstart"), 0x4545fba3 },
	{ T("endofmotd"), 0xc9406ccf },
	{ T("motd2"), 0x4a2c78e9 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ T("youreoper"), 0x4111abd1 },
	{ T("rehashing"), 0xa9600562 },
	{ NULL, 0 },
	{ T("myportis"), 0x77e6b6f6 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ T("time"), 0x9e3669da },
	{ T("usersstart"), 0xbe8d270d },
	{ T("users"), 0x14835dff },
	{ T("endofusers"), 0x4bfc54a9 },
	{ T("nousers"), 0x9a5d5914 },
};


/* the event names for 400 IRC msg codes */
event_name_t const irc_events_h_400[] =
{
	{ T("nosuchnick"), 0x9c6cc270 },
	{ T("nosuchserver"), 0x22ed2800 },
	{ T("nosuchchannel"), 0x8e3735ee },
	{ T("cannotsendtochan"), 0x2adbf541 },
	{ T("toomanychannels"), 0xcf87ff20 },
	{ T("wasnosuchnick"), 0xa773aae5 },
	{ T("toomanytargets"), 0xc75796f2 },
	{ T("noorigin"), 0xb71048da },
	{ NULL, 0 },
	{ T("norecipient"), 0xaf9bd029 },
	{ T("notexttosend"), 0xe3f9992c },
	{ T("notoplevel"), 0xc44d3b6d },
	{ T("wildtoplevel"), 0x6c688040 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ T("unknowncommand"), 0xe121cd9c },
	{ T("nomotd"), 0xa83ff78c },
	{ T("noadmininfo"), 0xd07036c5 },
	{ T("fileerror"), 0xb8f0b1b7 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ T("nonicknamegiven"), 0xd0506a97 },
	{ T("erroneusnickname"), 0x9fc3230a },
	{ T("nicknameinuse"), 0x6ff45115 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ T("nickcollision"), 0xfff9bcd4 },
	{ T("unavailresource"), 0x3e2ec1e9 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ T("usernotinchannel"), 0x603a411b },
	{ T("notonchannel"), 0x5c0b8730 },
	{ T("useronchannel"), 0xdcde9adc },
	{ T("nologin"), 0x9539e9e3 },
	{ T("summondisabled"), 0x2fb33168 },
	{ T("usersdisabled"), 0x28fdfbdf },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ T("notregistered"), 0x8dc78f50 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ T("needmoreparams"), 0x8906af44 },
	{ T("alreadyregistered"), 0xb96b0577 },
	{ T("nopermforhost"), 0xd63196d9 },
	{ T("passwdmismatch"), 0x8f05bd47 },
	{ T("yourebannedcreep"), 0x424e4d3c },
	{ T("youwillbebanned"), 0xacfcb611 },
	{ T("keyset"), 0x2f7ec56a },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ T("channelisfull"), 0x5f29fe09 },
	{ T("unknownmode"), 0x93898320 },
	{ T("inviteonlychan"), 0xcc392934 },
	{ T("bannedfromchan"), 0x0c0c3375 },
	{ T("badchannelkey"), 0x6c5988e4 },
	{ T("badchanmask"), 0x9b60fd06 },
	{ T("nochanmodes"), 0x8d3cdab4 },
	{ T("banlistfull"), 0xa012215b },
	{ NULL, 0 },
	{ NULL, 0 },
	{ T("noprivileges"), 0x1a772dd4 },
	{ T("chanoprivsneeded"), 0x177e5549 },
	{ T("cantkillserver"), 0x9fe917ca },
	{ T("restricted"), 0x3d96c542 },
	{ T("uniqopprivsneeded"), 0x9f07dc18 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ NULL, 0 },
	{ T("nooperhost"), 0x9444a9d6 },
	{ T("noservicehost"), 0x1d19329b },
};


/* the event names for 500 IRC msg codes */
event_name_t const irc_events_h_500[] =
{
	{ NULL, 0 },
	{ T("umodeunknownflag"), 0x40c76d91 },
	{ T("usersdontmatch"), 0x04f12e25 },
};

/* translate a command into an event name */
int8_t const * irc_event_get_name_from_cmd(irc_command_t const cmd)
{
	int32_t c;
	CHECK_RET(IS_VALID_EVENT(cmd), NULL);

	c = (int32_t)cmd;

	if ( (c > 0) && (c < 100) )
	{
		return irc_events_100[c];
	}
	else if ( (c >= 200) && (c < 300) )
	{
		return irc_events_200[c];
	}
	else if ( (c >= 300) && (c < 400) )
	{
		return irc_events_300[c];
	}
	else if ( (c >= 400) && (c < 500) ) 
	{
		return irc_events_400[c];
	}
	else if ( c >= 500 )
	{
		return irc_events_500[c];
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
		return irc_events_h_100[c].hash;
	}
	/*
	else if ( (c >= 200) && (c < 300) )
	{
		return irc_events_200[c];
	}
	else if ( (c >= 300) && (c < 400) )
	{
		return irc_events_300[c];
	}
	else if ( (c >= 400) && (c < 500) ) 
	{
		return irc_events_400[c];
	}
	else if ( c >= 500 )
	{
		return irc_events_500[c];
	}
	*/
	return 0;
}

