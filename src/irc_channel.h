#ifndef __IRC_CHANNEL__
#define __IRC_CHANNEL__

#if 0
int8_t const * const app_name = T("cbot 0.1");

/*
 * RFC 1459, Section 4.2.3.1 --
 *
 * "The various modes available for channels are as follows:
 *
 *         o - give/take channel operator privileges;
 *         p - private channel flag;
 *         s - secret channel flag;
 *         i - invite-only channel flag;
 *         t - topic settable by channel operator only flag;
 *         n - no messages to channel from clients on the outside;
 *         m - moderated channel;
 *         l - set the user limit to channel;
 *         b - set a ban mask to keep users out;
 *         v - give/take the ability to speak on a moderated channel;
 *         k - set a channel key (password)."
 */
typedef enum irc_modes_e
{
    mode_operator,
    mode_private,
    mode_secret,
    mode_invite_only,
    mode_topic_protect,
    mode_no_outside,
    mode_moderated,
    mode_user_limit,
    mode_ban_mask,
    mode_voice,
    mode_password,
    
    mode_last,
    mode_first = mode_operator,
    mode_count = mode_last - mode_first
} irc_modes_t;

/* the mode strings */
int8_t const * const irc_modes[mode_count] =
{
    T("o"),
    T("p"),
    T("s"),
    T("i"),
    T("t"),
    T("n"),
    T("m"),
    T("l"),
    T("b"),
    T("v"),
    T("k")
};

#define MODE_WORDS (1)

/* macros for setting, clearing and testing mode bits */
#define SET_MODE_BIT(x, y)      (x[(y / sizeof(uint32_t))] |= (uint32_t)(1 << (y % sizeof(uint32_t))))
#define CLEAR_MODE_BIT(x, y)    (x[(y / sizeof(uint32_t))] &= ~((uint32_t)(1 << (y % sizeof(uint32_t)))))
#define IS_MODE_BIT_SET(x, y)   (x[(y / sizeof(uint32_t))] & (uint32_t)(1 << (y % sizeof(uint32_t))))

#define IRC_BUFFER_SIZE (4 * 512)

typedef struct irc_client_s
{
    int8_t*     nick;           /* nick */
    int8_t*     user_name;      /* user name */
    int8_t*     real_name;      /* real name */
    int8_t*     nickserv_pass;  /* nickserv pass, only used for local client */
    int32_t     mode[MODE_WORDS];/* mode flags */
} irc_client_t;

typedef struct irc_channel_s
{
    int8_t*     name;           /* name of the channel */
    int8_t*     pass;           /* the channel password */
    int8_t*     topic;          /* channel topic */
    int32_t     mode[MODE_WORDS];/* mode flags */
    array_t*    clients;        /* array of clients in the channel (irc_client_t*) */
} irc_channel_t;

#endif

#endif
