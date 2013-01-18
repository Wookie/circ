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


#ifndef IRC_UTIL_H
#define IRC_UTIL_H

typedef struct msgto_s
{
	uint8_t * channel;
	uint8_t * user;
	uint8_t * hostname;
	uint8_t * hostaddr_ipv4;
	uint8_t * hostaddr_ipv6;
	uint8_t * server_name;
} msgto_t;

int parse_prefix( uint8_t * start, uint8_t ** nick, uint8_t ** user, 
				  uint8_t ** host, uint8_t ** ipv4, uint8_t ** ipv6 );

int parse_msgtarget( uint8_t * start, msgto_t ** msgtos, int * nmsgtos );

#endif/*IRC_UTIL_H*/

