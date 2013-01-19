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


static int is_letter( uint8_t const c )
{
	return ( ( (c >= 'a') && (c <= 'z') ) ||
			 ( (c >= 'A') && (c <= 'Z') ) );
}

static int is_digit( uint8_t const c )
{
	return ( (c >= '0') && (c <= '9') );
}

static int is_hex( uint8_t const c )
{
	return ( is_digit(c) ||
			 ( (c >= 'A') && (c <= 'F') ) ||
			 ( (c >= 'a') && (c <= 'f') ) );
}

static int is_special( uint8_t const c )
{
	return ( ( (c >= 0x5B) && (c <= 0x60) ) ||
			 ( (c >= 0x7B) && (c <= 0x7D) ) );
}

static int is_user_octet( uint8_t const c )
{
	return ( ( (c >= 0x01) && (c <= 0x09) ) ||
			 ( (c >= 0x0B) && (c <= 0x0C) ) ||
			 ( (c >= 0x0E) && (c <= 0x1F) ) ||
			 ( (c >= 0x21) && (c <= 0x3F) ) ||
			 ( (c >= 0x41) && (c <= 0xFF) ) );
}

static int is_key_octet( uint8_t const c )
{
	return ( ( (c >= 0x01) && (c <= 0x05) ) ||
			 ( (c >= 0x07) && (c <= 0x08) ) ||
			 ( (c == 0x0C)				  ) ||
			 ( (c >= 0x0E) && (c <= 0x1F) ) ||
			 ( (c >= 0x21) && (c <= 0x7F) ) );
}

static int is_chanstart( uint8_t const c )
{
	return ( ( c == '#' ) ||
			 ( c == '+' ) ||
			 ( c == '!' ) ||
			 ( c == '&' ) );
}

static int is_chanstring( uint8_t const c )
{
	return ( ( (c >= 0x01) && (c <= 0x07) ) ||
			 ( (c >= 0x08) && (c <= 0x09) ) ||
			 ( (c >= 0x0B) && (c <= 0x0C) ) ||
			 ( (c >= 0x0E) && (c <= 0x1F) ) ||
			 ( (c >= 0x21) && (c <= 0x2B) ) ||
			 ( (c >= 0x2D) && (c <= 0x39) ) ||
			 ( (c >= 0x3B) && (c <= 0xFF) ) );
}

static int check_ipv4_part( uint8_t * pstart, uint8_t *pend )
{
	int value;
	uint8_t buf[4];
	CHECK_PTR_RET( pstart, FALSE );
	CHECK_PTR_RET( pend, FALSE );
	CHECK_RET( ((void*)pend - (void*)pstart) > 3, FALSE );
	MEMCPY( buf, pstart, 3 );
	buf[3] = '\0';
	value = atoi( buf );
	return ( (value >= 0) && (value <= 255) );
}

static int parse_ipv4( uint8_t * start, uint8_t ** end, uint8_t ** ipv4 )
{
	int parts = 0;
	uint8_t * p = NULL;
	uint8_t * part = NULL;

	CHECK_PTR_RET( start, FALSE );
	CHECK_PTR_RET( end, FALSE );

	p = start;
	part = p;

	while ( *p != '\0' )
	{
		if ( *p == '.' )
		{
			if ( !check_ipv4_part( part, p ) )
			{
				WARN( "invalid IPv4 octet\n" );
				return FALSE;
			}
			p++;
			parts++;
			part = p;

			if ( parts > 3 )
			{
				WARN( "too many IPv4 octets\n" );
				return FALSE;
			}

			continue;
		}

		if ( is_digit( *p ) )
		{
			p++;
			continue;
		}

		WARN( "failed to parse IPV4 at position %d (%#x)\n", (int)((void*)p - (void*)start), *p );
		return FALSE;
	}

	/* check the last part */
	if ( !check_ipv4_part( part, p ) )
	{
		WARN( "invalid IPv4 octet\n" );
		return FALSE;
	}

	/* make sure we saw the correct number of '.' */
	if ( parts != 3 )
	{
		WARN( "invalid number of IPv4 octets\n" );
		return FALSE;
	}

	(*end) = p;

	/* return the ipv4 addr */
	if ( ipv4 != NULL )
		(*ipv4) = start;

	return TRUE;
}

static int parse_ipv6( uint8_t * start, uint8_t ** end, uint8_t ** ipv6 )
{
	uint8_t * p = NULL;
	uint8_t * part = NULL;

	CHECK_PTR_RET( start, FALSE );
	CHECK_PTR_RET( end, FALSE );
	p = start;
	part = p;

	while( *p != '\0' )
	{
		if ( is_hex(*p) || (*p == ':') )
		{
			p++;
			continue;
		}

		WARN( "ipv6 failed to parse at position %d (%#x)\n", (int)((void*)p - (void*)start), *p );
		return FALSE;
	}

	(*end) = p;

	if ( ipv6 != NULL )
		(*ipv6) = start;

	return TRUE;
}

static int parse_hostname( uint8_t * start, uint8_t ** end )
{
	int first = TRUE;
	uint8_t * p = NULL;

	CHECK_PTR_RET( start, FALSE );
	CHECK_PTR_RET( end, FALSE );
	p = start;

	while ( *p != '\0' )
	{
		if ( first )
		{
			if ( is_letter(*p) || is_digit(*p) )
			{
				first = FALSE;
				p++;
				continue;
			}

			WARN( "hostname failed to parse at position %d (%#x)\n", (int)((void*)p - (void*)start), *p );
			return FALSE;
		}

		if ( *p == '.' )
		{
			first = TRUE;
			p++;
			continue;
		}

		if ( is_letter(*p) || is_digit(*p) || (*p == '-') )
		{
			p++;
			continue;
		}

		WARN( "hostname failed to parse at position %d (%#x)\n", (int)((void*)p - (void*)start), *p );
		return FALSE;
	}

	/* found the end of the hostname */
	(*end) = p;
	return TRUE;
}


static int parse_user( uint8_t * start, uint8_t ** end, uint8_t ** user )
{
	uint8_t * p = NULL;

	CHECK_PTR_RET( start, FALSE );
	CHECK_PTR_RET( end, FALSE );
	p = start;

	while( (*p != '\0') && (*p != '@') && (*p != '%') )
	{
		if ( is_user_octet( *p ) )
		{
			p++;
			continue;
		}

		WARN( "user failed to parse at position %d (%#x)\n", (int)((void*)p - (void*)start), *p );
		return FALSE;
	}

	/* we got a valid user */
	(*end) = p;

	/* return the user */
	if ( user != NULL )
		(*user) = start;

	return TRUE;
}

static int parse_nick( uint8_t * start, uint8_t ** end, uint8_t ** nick )
{
	int first = TRUE;
	uint8_t * p = NULL;

	CHECK_PTR_RET( start, FALSE );
	CHECK_PTR_RET( end, FALSE );
	p = start;

	while( (*p != '\0') && (*p != '!') && (*p != '@') )
	{
		if ( first )
		{
			if ( is_letter( *p ) || is_special( *p ) )
			{
				first = FALSE;
				p++;
				continue;
			}

			WARN( "nick failed to parse at position %d (%#x)\n", (int)((void*)p - (void*)start), *p );
			return FALSE;
		}

		if ( ((void*)p - (void*)start) > 9 )
		{
			WARN( "invalid nickname is too long > 9 characters" );
			return FALSE;
		}

		if ( is_letter( *p ) || is_digit( *p ) || is_special( *p ) || (*p == '-') )
		{
			p++;
			continue;
		}

		WARN( "nick failed to parse at position %d (%#x)\n", (int)((void*)p - (void*)start), *p );
		return FALSE;
	}

	/* we got a valid nick */
	(*end) = p;

	/* return the nick */
	if ( nick != NULL )
		(*nick) = start;

	return TRUE;
}

static int parse_shortname( uint8_t * start, uint8_t ** end, uint8_t ** shortname )
{
	int first = TRUE;
	uint8_t * p;
	uint8_t * dash;

	CHECK_PTR_RET( start, FALSE );
	CHECK_PTR_RET( end, FALSE );

	p = start;
	while( (*p != '\0') && (*p != '.') )
	{
		if ( first )
		{
			if ( is_letter( *p ) || (is_digit( *p ) ) )
			{
				p++;
				first = FALSE;
				continue;
			}
		}
		else if ( *p == '-' )
		{
			dash = p;
			p++;
			continue;
		}
		else if ( is_letter( *p ) || is_digit( *p ) )
		{
			p++;
			dash = NULL;
			continue;
		}
		WARN( "shortname failed to parse at position %d (%#x)\n", (int)((void*)p - (void*)start), *p );
		return FALSE;
	}

	if ( dash != NULL )
	{
		WARN( "shortname failed to parse at position %d (%#x)\n", (int)((void*)dash - (void*)start), *dash );
		return FALSE;
	}

	(*end) = p;

	/* return the shortname */
	if ( shortname != NULL )
		(*shortname) = start;

	return TRUE;
}

static int parse_hostname( uint8_t * start, uint8_t ** end, uint8_t ** hostname )
{
	uint8_t * p;
	uint8_t * pend = NULL;
	uint8_t * dot = NULL;

	CHECK_PTR_RET( start, FALSE );
	CHECK_PTR_RET( end, FALSE );
	CHECK_PTR_RET( hostname, FALSE );

	p = start;
	while( *p != '\0' )
	{
		if ( !parse_shortname( p, &pend ) )
		{
			WARN( "hostname failed to parse at position %d (%#x)\n", (int)((void*)p - (void*)start), *p );
			return FALSE;
		}
		else
		{
			dot = NULL;
			p = pend;
		}

		if ( *p == '\0' )
			continue;

		if ( ((void*)p - (void*)start) > 63 )
		{
			WARN( "invalid hostname is too long > 63 characters" );
			return FALSE;
		}

		if ( *p == '.' )
		{
			dot = p;
			p++;
			continue;
		}
		
		WARN( "hostname failed to parse at position %d (%#x)\n", (int)((void*)p - (void*)start), *p );
		return FALSE;
	}

	if ( dot != NULL )
	{
		WARN( "hostname failed to parse at position %d (%#x)\n", (int)((void*)dot - (void*)start), *dot );
		return FALSE;
	}

	(*end) = p;
	(*hostname) = start;
	return TRUE;
}

static int parse_hostaddr( uint8_t * start, uint8_t ** end, uint8_t ** ipv4, uint8_t ** ipv6 )
{
	uint8_t * p = NULL;
	uint8_t * pend = NULL;

	CHECK_PTR_RET( start, FALSE );
	CHECK_PTR_RET( end, FALSE );

	p = start;

	if ( parse_ipv4( p, &pend, ipv4 ) )
	{
		(*end) = pend;
		if ( ipv6 != NULL )
			(*ipv6) = NULL;
		return TRUE;
	}

	if ( parse_ipv6( p, &pend, ipv6 ) )
	{
		(*end) = pend;
		if ( ipv4 != NULL )
			(*ipv4) = NULL;
		return TRUE;
	}

	WARN( "hostaddr failed to parse at position %d (%#x)\n", (int)((void*)p - (void*)start), *p );
	return FALSE;
}

static int parse_servername( uint8_t * start, uint8_t ** end, uint8_t ** servername )
{
	return parse_hostname( start, end, servername );
}

static int parse_host( uint8_t * start, uint8_t ** end, uint8_t ** hostname, uint8_t ** ipv4, uint8_t ** ipv6 )
{
	uint8_t * p = NULL;
	uint8_t ** pend = NULL;

	CHECK_PTR_RET( start, FALSE );
	CHECK_PTR_RET( end, FALSE );

	p = start;

	if ( parse_hostname( p, &pend, hostname ) )
	{
		(*end) = pend;
		if ( ipv4 != NULL )
			(*ipv4) = NULL;
		if ( ipv6 != NULL )
			(*ipv6) = NULL;
		return TRUE;
	}

	if ( parse_hostaddr( p, &pend, ipv4, ipv6 ) )
	{
		(*end) = pend;
		if ( hostname != NULL )
			(*hostname) = NULL;
		return TRUE;
	}

	WARN( "host failed to parse at position %d (%#x)\n", (int)((void*)p - (void*)start), *p );
	return FALSE;
}

static int parse_channel( uint8_t * start, uint8_t ** end, uint8_t ** channel )
{
	uint8_t * p = NULL;
	int first = TRUE;
	
	CHECK_PTR_RET( start, FALSE );
	CHECK_PTR_RET( end, FALSE );

	p = start;

	while ( (*p != '\0') && (*p != ' ') )
	{
		if ( first )
		{
			if ( !is_chanstart( *p ) )
			{
				WARN( "channel name failed to parse at position %d (%#x)\n", (int)((void*)p - (void*)start), *p );
				return FALSE;
			}
			first = FALSE;
			p++;
			continue;
		}
				

		if ( is_chanstring( *p ) )
		{
			p++;
		}

		if ( ((void*)p - (void*)start) > 50 )
		{
			WARN( "invalid channel name is too long > 50 characters" );
			return FALSE;
		}
	}

	(*end) = p;

	if ( channel != NULL )
		(*channel) = start;
}

int parse_msgto( uint8_t * start, uint8_t ** end, msgto_t * mt )
{
	uint8_t * p = NULL;
	uint8_t * pend = NULL;
	uint8_t * usernick = NULL;

	CHECK_PTR_RET( start, FALSE );
	CHECK_PTR_RET( end, FALSE );
	CHECK_PTR_RET( mt, FALSE );

	MEMSET( mt, 0, sizeof( msgto_t ) );

	p = start;

	if ( parse_channel( p, &pend, &(mt->channel) ) )
	{
		(*end) = pend;
		return TRUE;
	}
/*
	if ( parse_user( p, &pend, &usernick ) )
	{
		if ( *p == '%' )
		{
		}
		else if ( *p == '!' )
*/
	return FALSE;
}

int parse_prefix( uint8_t * start, uint8_t ** nick, uint8_t ** user, 
				  uint8_t ** host, uint8_t ** ipv4, uint8_t ** ipv6 )
{
	uint8_t * p;
	uint8_t * pend = NULL;

	CHECK_PTR_RET( start, FALSE );

	p = start;

	/* see if we have a servername */
	if ( parse_servername( p, &pend, host ) )
	{
		CHECK_RET( (p == '\0'), FALSE );
		return TRUE;
	}

	/* if we get here, then we must have a ( nickname [ [ "!" user ] "@" host ] ) */

	/* try to parse the nickname */
	if ( parse_nick( p, &pend, nick) )
	{
		p = pcur;
	}
	else
	{
		WARN( "prefix failed to parse at position %d (%#x)\n", (int)((void*)p - (void*)start), *p );
		return FALSE;
	}

	/* see if it was just a nick */
	if ( p == '\0' )
		return TRUE;

	if ( p == '!' )
	{
		*p = '\0';
		p++;

		/* now parse the user */
		if ( parse_user( p, &pend, user) )
		{
			p = pend;
			if ( host != NULL )
				(*host) = NULL;
			if ( ipv4 != NULL )
				(*ipv4) = NULL;
			iv ( ipv6 != NULL )
				(*ipv6) = NULL;
		}
		else
		{
			WARN( "prefix failed to parse at position %d (%#x)\n", (int)((void*)p - (void*)start), *p );
			return FALSE;
		}
	}
	else if ( p == '@' )
	{
		*p = '\0';
		p++;

		/* now parse the host */
		if ( parse_host( p, &pend, host, ipv4, ipv6 ) )
		{
			p = pend;
			if ( user != NULL )
				(*user) = NULL;
		}
		else
		{
			WARN( "prefix failed to parse at position %d (%#x)\n", (int)((void*)p - (void*)start), *p );
			return FALSE;
		}
	}
	else
	{
		WARN( "prefix failed to parse at position %d (%#x)\n", (int)((void*)p - (void*)start), *p );
		return FALSE;
	}

	return TRUE;
}

int parse_msgtarget( uint8_t * start, msgto_t ** msgtos, int * nmsgtos )
{
	int n = 1;
	uint8_t * p = NULL;
	uint8_t * pend = NULL;
	msgto_t * mts = NULL;

	CHECK_PTR_RET( start, FALSE );
	CHECK_PTR_RET( msgtos, FALSE );
	CHECK_PTR_RET( nmsgtos, FALSE );

	p = start;

	while( *p != '\0' )
	{
		/* increase the array size by one */
		mts = REALLOC( mts, n * sizeof( msgto_t ) );
		if ( parse_msgto( p, &pend, &mts[n - 1] ) )
		{
			p = pend;

			if ( *p == ',' )
			{
				p++;
				n++;
			}
			continue;
		}

		WARN( "msgtarget failed to parse at position %d (%#x)\n", (int)((void*)p - (void*)start), *p );
		FREE( mts );
		(*msgtos) = NULL;
		(*nmsgtos) = 0;
		return FALSE;
	}

	(*msgtos) = mts;
	(*nmsgtos) = n;
	return TRUE;
}

