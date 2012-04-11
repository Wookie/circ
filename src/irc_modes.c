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

#include "irc_modes.h"

static int8_t const * const umodes = "abcdfghiklmnopqrstuvwxyzABCGHINORSTVW";

irc_umode_t a_to_umode( int8_t const c )
{
	int8_t const * p = umodes;
	while ( (*p) != '\0' )
	{
		if ( (*p) == c )
			break;
		++p;
	}
	return (irc_umode_t)(p - umodes);
}

static int8_t const * const cmodes = "abcdefhijklmnopqrstuvz!ACDGHIJKLMNOQRSV";

irc_cmode_t a_to_cmode( int8_t const c )
{
	int8_t const * p = cmodes;
	while ( (*p) != '\0' )
	{
		if ( (*p) == c )
			break;
		++p;
	}
	return (irc_cmode_t)(p - cmodes);
}

static int8_t const * const smodes = "ahlnsADFHLMT";

irc_smode_t a_to_smode( int8_t const c )
{
	int8_t const * p = smodes;
	while ( (*p) != '\0' )
	{
		if ( (*p) == c )
			break;
		++p;
	}
	return (irc_smode_t)(p - smodes);
}

