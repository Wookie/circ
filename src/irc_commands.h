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
 
#ifndef __IRC_COMMANDS_H__
#define __IRC_COMMANDS_H__

typedef enum irc_ret_e
{
    /* non-error return value */
    IRC_OK              = 1,
    IRC_MSG_MOREDATA    = 2,
    IRC_CONTINUE		= 3,
    
    /* errors */
    IRC_ERR             = -1,
    IRC_BADPARAM        = -2,
    IRC_SOCKET_ERROR    = -3,
    IRC_BAD_MESSAGE     = -4,
    IRC_BAD_STATE       = -5
        
} irc_ret_t;

#define CMD_BASE (10000)

typedef enum irc_command_e
{
	/* used to indicate any command */
	ANYCMD = -2,

    /* used when no command is specified */
    NOCMD = -1,
    
    /* RFC 2812, Section 3 -- Message Details */
    
    /* RFC 2812, Section 3.1 -- Connection Registration */
    PASS = CMD_BASE,
    NICK,
    USER,
    OPER,
    MODE,
    SERVICE,
    QUIT,
    SQUIT,

    /* RFC 2812, Section 3.2 -- Channel Operations */
    JOIN,
    PART,
    /* MODE */  /* also a connection registration command */
    TOPIC,
    NAMES,
    LIST,
    INVITE,
    KICK,
    
    /* RFC 2812, Section 3.3 -- Sending Messages */
    PRIVMSG,
    NOTICE,
    
    /* RFC 2812, Section 3.4 -- Server Queries and Commands */
    MOTD,
    LUSERS,
    VERSION,
    STATS,
    LINKS,
    TIME,
    CONNECT,
    TRACE,
    ADMIN,
    INFO,
        
    /* RFC 2812, Section 3.5 -- Service Query and Commands */
    SERVLIST,
    SQUERY,
    
    /* RFC 2812, Section 3.6 -- User Based Queries */
    WHO,
    WHOIS,
    WHOWAS,
    
    /* RFC 2812, Section 3.7 -- Misc Messages */
    KILL,
    PING,
    PONG,
    ERROR,
    
    /* RFC 2812, Section 4 -- Optional Features */
    AWAY,
    REHASH,
    DIE,
    RESTART,
    SUMMON,
    USERS,
    WALLOPS,
    USERHOST,
    ISON,
    
    /* helpers for checking command validity */
    LAST_COMMAND,
    FIRST_COMMAND = PASS,
    NUM_COMMANDS = LAST_COMMAND - FIRST_COMMAND,
    
    /* RFC 2812, Section 5 -- Replies */
    
    /* 
     * RFC 2812, Section 5.1 -- Command Responses
     * Numerics in the range from 001 to 099 are used for 
     * client-server connections only and should never travel 
     * between servers.  Replies generated in the response to
     * commands are found in the range from 200 to 399.
     */
    RPL_WELCOME             = 1,
    RPL_YOURHOST            = 2,
    RPL_CREATED             = 3,
    RPL_MYINFO              = 4,
    RPL_BOUNCE              = 5,   /* RFC2812 */
    RPL_ISUPPORT			= 5,
    RPL_MAP					= 6,   /* Unreal */
    RPL_MAPEND				= 7,   /* Unreal */
    RPL_SNOMASK				= 8,   /* ircu */
    RPL_STATMENTOT			= 9,   /* ircu */
    RPL_BOUNCE_2			= 10,
	RPL_STATMEM				= 10,  /* ircu */
	
	RPL_YOURCOOKIE			= 14,  /* Hybrid? */
	RPL_MAP_2				= 15,  /* ircu */
	RPL_MAPMORE				= 16,  /* ircu */
	RPL_MAPEND_2			= 17,  /* ircu */
	
	RPL_YOURID				= 42,  /* IRCnet */
	RPL_SAVENICK			= 43,  /* IRCnet */
	
	RPL_ATTEMPTINGJUNC		= 50,  /* aircd */
	RPL_ATTEMPTINGREROUTE   = 51,  /* aircd */
    
    RPL_TRACELINK           = 200,
    RPL_TRACECONNECTING     = 201,
    RPL_TRACEHANDSHAKE      = 202,
    RPL_TRACEUNKNOWN        = 203,
    RPL_TRACEOPERATOR       = 204,
    RPL_TRACEUSER           = 205,
    RPL_TRACESERVER         = 206,
    RPL_TRACENEWTYPE        = 208,
    RPL_TRACECLASS          = 209,
    RPL_TRACERECONNECT      = 210,
    RPL_STATSLINKINFO       = 211,
    RPL_STATSCOMMANDS       = 212,
    RPL_STATSCLINE          = 213, /* reserved */
    RPL_STATSNLINE          = 214, /* reserved */
    RPL_STATSILINE          = 215, /* reserved */
    RPL_STATSKLINE          = 216, /* reserved */
    RPL_STATSQLINE          = 217, /* reserved */
    RPL_STATSYLINE          = 218, /* reserved */
    RPL_ENDOFSTATS          = 219,
    RPL_UMODEIS             = 221,
    RPL_SERVICEINFO         = 231, /* reserved */
    RPL_ENDOFSERVICES       = 232, /* reserved */
    RPL_SERVICE             = 233, /* reserved */
    RPL_SERVLIST            = 234,
    RPL_SERVLISTEND         = 235,
    RPL_STATSVLINE          = 240, /* reserved */
    RPL_STATSLLINE          = 241, /* reserved */
    RPL_STATSUPTIME         = 242,
    RPL_STATSOLINE          = 243,
    RPL_STATSHLINE          = 244, /* reserved */
    RPL_STATSPING           = 246, /* reserved */
    RPL_STATSBLINE          = 247, /* reserved */
    RPL_STATSDLINE          = 250, /* reserved */
    RPL_LUSERCLIENT         = 251,
    RPL_LUSEROP             = 252,
    RPL_LUSERUNKNOWN        = 253,
    RPL_LUSERCHANNELS       = 254,
    RPL_LUSERME             = 255,
    RPL_ADMINME             = 256,
    RPL_ADMINLOC1           = 257,
    RPL_ADMINLOC2           = 258,
    RPL_ADMINEMAIL          = 259,
    RPL_TRACELOG            = 261,
    RPL_TRACEEND            = 262,
    RPL_TRYAGAIN            = 263,
    
    RPL_LOCALUSERS			= 265,
    RPL_GLOBALUSERS			= 266,
    RPL_START_NETSTAT		= 267,
    RPL_NETSTAT				= 268,
    RPL_END_NETSTAT			= 269,
    /* more from http://www.alien.net.au/irc/irc2numerics.html */
    
    RPL_NONE                = 300, /* reserved */
    RPL_AWAY                = 301,
    RPL_USERHOST            = 302,
    RPL_ISON                = 303,
    RPL_UNAWAY              = 305,
    RPL_NOWAWAY             = 306,
    RPL_WHOISUSER           = 311,
    RPL_WHOISSERVER         = 312,
    RPL_WHOISOPERATOR       = 313,
    RPL_WHOWASUSER          = 314,
    RPL_ENDOFWHO            = 315,
    RPL_WHOISCHANOP         = 316, /* reserved */
    RPL_WHOISIDLE           = 317,
    RPL_ENDOFWHOIS          = 318,
    RPL_WHOISCHANNELS       = 319,
    RPL_LISTSTART           = 321,
    RPL_LIST                = 322,
    RPL_LISTEND             = 323,
    RPL_CHANNELMODEIS       = 324,
    RPL_UNIQOPIS            = 325,
    RPL_CHANNELCREATEDON    = 329,
    RPL_NOTOPIC             = 331,
    RPL_TOPIC               = 332,
    RPL_INVITING            = 341,
    RPL_SUMMONING           = 342,
    RPL_INVITELIST          = 346,
    RPL_ENDOFINVITELIST     = 347,
    RPL_EXCEPTLIST          = 348,
    RPL_ENDOFEXCEPTLIST     = 349,
    RPL_VERSION             = 351,
    RPL_WHOREPLY            = 352,
    RPL_NAMREPLY            = 353,
    RPL_KILLDONE            = 361, /* reserved */
    RPL_CLOSING             = 362, /* reserved */
    RPL_CLOSEEND            = 363, /* reserved */
    RPL_LINKS               = 364,
    RPL_ENDOFLINKS          = 365,
    RPL_ENDOFNAMES          = 366,
    RPL_BANLIST             = 367,
    RPL_ENDOFBANLIST        = 368,
    RPL_ENDOFWHOWAS         = 369,
    RPL_INFO                = 371,
    RPL_MOTD                = 372,
    RPL_INFOSTART           = 373, /* reserved */
    RPL_ENDOFINFO           = 374,
    RPL_MOTDSTART           = 375,
    RPL_ENDOFMOTD           = 376,
    RPL_YOUREOPER           = 381,
    RPL_REHASHING           = 382,
    RPL_YOURESERVICE        = 383,
    RPL_MYPORTIS            = 384, /* reserved */
    RPL_TIME                = 391,
    RPL_USERSSTART          = 392,
    RPL_USERS               = 393,
    RPL_ENDOFUSERS          = 394,
    RPL_NOUSERS             = 395,
    
    /* RFC 2812, Section 5.2 -- Error Replies */
    ERR_NOSUCHNCK           = 401,
    ERR_NOSUCKSERVER        = 402,
    ERR_NOSUCHCHANNEL       = 403,
    ERR_CANNOTSENDTOCHAN    = 404,
    ERR_TOOMANYCHANNELS     = 405,
    ERR_WASNOSUCHNICK       = 406,
    ERR_TOOMANYTARGETS      = 407,
    ERR_NOORIGIN            = 409,
    ERR_NORECEIPIENT        = 411,
    ERR_NOTEXTTOSEND        = 412,
    ERR_NOTOPLEVEL          = 413,
    ERR_WILDTOPLEVEL        = 414,
    ERR_BADMASK             = 415,
    ERR_UNKNOWNCOMMAND      = 421,
    ERR_NOMOTD              = 422,
    ERR_NOADMININFO         = 423,
    ERR_FILEERROR           = 424,
    ERR_NONICKNAMEGIVEN     = 431,
    ERR_ERRONEUSNCKNAME     = 432,
    ERR_NICKNAMEINUSE       = 433,
    ERR_NICKCOLLISION       = 436,
    ERR_UNAVAILRESOURCE     = 437,
    ERR_USERNOTINCHANNEL    = 441,
    ERR_NOTONCHANNEL        = 442,
    ERR_USERONCHANNEL       = 443,
    ERR_NOLOGIN             = 444,
    ERR_SUMMONDISABLED      = 445,
    ERR_USERSDISABLED       = 446,
    ERR_NOTREGISTERED       = 451,
    ERR_NEEDMOREPARAMS      = 461,
    ERR_ALREADYREGISTERED   = 462,
    ERR_NOPERMFORHOST       = 463,
    ERR_PASSWDMISMATCH      = 464,
    ERR_YOUREBANNEDCREEP    = 465,
    ERR_YOUWILLBEBANNED     = 466,
    ERR_KEYSET              = 467,
    ERR_CHANNELISFULL       = 471,
    ERR_UNKNOWNMODE         = 472,
    ERR_INVITEONLYCHAN      = 473,
    ERR_BANNEDFROMCHAN      = 474,
    ERR_BADCHANNELKEY       = 475,
    ERR_BADCHANMASK         = 476,
    ERR_NOCHANMODES         = 477,
    ERR_BANLISTFULL         = 478,
    ERR_NORIVILEGES         = 481,
    ERR_CHANOPRIVSNEEDED    = 482,
    ERR_CANTKILLSERVER      = 483,
    ERR_RESTRICTED          = 484,
    ERR_UNIQOPPRIVSNEEDED   = 485,
    ERR_NOOPERHOST          = 491,
    ERR_NOSERVICEHOST       = 492, /* reserved */
    ERR_UMODEUNKNOWNFLAG    = 501,
    ERR_USERSDONTMATCH      = 502

} irc_command_t;

#define IS_ERROR(x) ((x >= 400) && (x < FIRST_COMMAND))
#define IS_REPLY(x) ((x >= 1) && (x < 400))
#define IS_COMMAND(x) ((x >= FIRST_COMMAND) && (x < LAST_COMMAND))
#define IS_RESERVED(x) ( \
    (x == RPL_STATSCLINE) || \
    (x == RPL_STATSNLINE) || \
    (x == RPL_STATSILINE) || \
    (x == RPL_STATSKLINE) || \
    (x == RPL_STATSQLINE) || \
    (x == RPL_STATSYLINE) || \
    (x == RPL_SERVICEINFO) || \
    (x == RPL_ENDOFSERVICES) || \
    (x == RPL_SERVICE) || \
    (x == RPL_STATSVLINE) || \
    (x == RPL_STATSLLINE) || \
    (x == RPL_STATSHLINE) || \
    (x == RPL_STATSPING) || \
    (x == RPL_STATSBLINE) || \
    (x == RPL_STATSDLINE) || \
    (x == RPL_NONE) || \
    (x == RPL_WHOISCHANOP) || \
    (x == RPL_KILLDONE) || \
    (x == RPL_CLOSING) || \
    (x == RPL_CLOSEEND) || \
    (x == RPL_INFOSTART) || \
    (x == RPL_MYPORTIS) || \
    (x == ERR_NOSERVICEHOST))
#define IS_VALID_COMMAND(x) (IS_ERROR(x) || IS_REPLY(x) || IS_COMMAND(x) || (x == NOCMD))

/* translate a command into a string */
int8_t const * irc_cmd_get_string( irc_command_t const cmd );

/* translate a command into its type string */
int8_t const * irc_cmd_get_type_string( irc_command_t const cmd );

/* translate a string into a command number */
irc_command_t irc_cmd_get_command_from_string( int8_t const * const str );

#endif//__IRC_COMMANDS_H__
