/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Derived from mod_remoteip.c.
 * Default values for directives are hard-wired for CloudFlare defaults.
 *
 * Supported directives and example values (further info in README):
 *
 * CloudFlareRemoteIPHeader CF-Connecting-IP
 * CloudFlareRemoteIPTrustedProxy 204.93.173.0/24
 * DenyAllButCloudFlare
 *
 */

#include "ap_config.h"
#include "ap_mmn.h"
#include "httpd.h"
#include "http_config.h"
#include "http_connection.h"
#include "http_protocol.h"
#include "http_log.h"
#include "apr_strings.h"
#include "apr_lib.h"
#define APR_WANT_BYTEFUNC
#include "apr_want.h"
#include "apr_network_io.h"

module AP_MODULE_DECLARE_DATA cloudflare_module;

#define CF_DEFAULT_IP_HEADER "CF-Connecting-IP"
/* CloudFlare IP Ranges from https://www.cloudflare.com/ips */
static const char* CF_DEFAULT_TRUSTED_PROXY[] = {
/* IPv4 Address Ranges */
  "103.21.244.0/22",
  "103.22.200.0/22",
  "103.31.4.0/22",
  "104.16.0.0/12",
  "108.162.192.0/18",
  "131.0.72.0/22",
  "141.101.64.0/18",
  "162.158.0.0/15",
  "172.64.0.0/13",
  "173.245.48.0/20",
  "188.114.96.0/20",
  "190.93.240.0/20",
  "197.234.240.0/22",
  "198.41.128.0/17",
/* IPv6 Address Ranges */
  "2400:cb00::/32",
  "2405:8100::/32",
  "2405:b500::/32",
  "2606:4700::/32",
  "2803:f800::/32",
  "2c0f:f248::/32",
  "2a06:98c0::/29",
};
static const size_t CF_DEFAULT_TRUSTED_PROXY_COUNT = 
  sizeof(CF_DEFAULT_TRUSTED_PROXY)/sizeof(char *);

typedef struct {
    /** A proxy IP mask to match */
    apr_ipsubnet_t *ip;
    /** Flagged if internal, otherwise an external trusted proxy */
    void  *internal;
} cloudflare_proxymatch_t;

typedef struct {
    /** The header to retrieve a proxy-via ip list */
    const char *header_name;
    /** A header to record the proxied IP's
     * (removed as the physical connection and
     * from the proxy-via ip header value list)
     */
    const char *proxies_header_name;
    /** A list of trusted proxies, ideally configured
     *  with the most commonly encountered listed first
     */

    int deny_all;
    /** If this flag is set, only allow requests which originate from a CF Trusted Proxy IP.
     * Return 403 otherwise.
     */
    apr_array_header_t *proxymatch_ip;
} cloudflare_config_t;

typedef struct {
    /** The previous proxy-via request header value */
    const char *prior_remote;
    /** The unmodified original ip and address */
    const char *orig_ip;
    apr_sockaddr_t *orig_addr;
    /** The list of proxy ip's ignored as remote ip's */
    const char *proxy_ips;
    /** The remaining list of untrusted proxied remote ip's */
    const char *proxied_remote;
    /** The most recently modified ip and address record */
    const char *proxied_ip;
    apr_sockaddr_t proxied_addr;
} cloudflare_conn_t;

static apr_status_t set_cf_default_proxies(apr_pool_t *p, cloudflare_config_t *config);

static void *create_cloudflare_server_config(apr_pool_t *p, server_rec *s)
{
    cloudflare_config_t *config = apr_pcalloc(p, sizeof *config);
    /* config->header_name = NULL;
     * config->proxies_header_name = NULL;
     */
    if (config == NULL) {
        return NULL;
    }
    if (set_cf_default_proxies(p, config) != APR_SUCCESS) {
        return NULL;
    }
    config->header_name = CF_DEFAULT_IP_HEADER;
    return config;
}

static void *merge_cloudflare_server_config(apr_pool_t *p, void *globalv,
                                            void *serverv)
{
    cloudflare_config_t *global = (cloudflare_config_t *) globalv;
    cloudflare_config_t *server = (cloudflare_config_t *) serverv;
    cloudflare_config_t *config;

    config = (cloudflare_config_t *) apr_palloc(p, sizeof(*config));
    config->header_name = server->header_name
                        ? server->header_name
                        : global->header_name;
    config->proxies_header_name = server->proxies_header_name
                                ? server->proxies_header_name
                                : global->proxies_header_name;
    config->proxymatch_ip = server->proxymatch_ip
                          ? server->proxymatch_ip
                          : global->proxymatch_ip;
    config->deny_all = server->deny_all
                     ? server->deny_all
                     : global->deny_all;
    return config;
}

static const char *header_name_set(cmd_parms *cmd, void *dummy,
                                   const char *arg)
{
    cloudflare_config_t *config = ap_get_module_config(cmd->server->module_config,
                                                       &cloudflare_module);
    config->header_name = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

static const char *deny_all_set(cmd_parms *cmd, void *dummy)
{
    cloudflare_config_t *config = ap_get_module_config(cmd->server->module_config,
                                                       &cloudflare_module);
    config->deny_all = 1;
    return NULL;
}

/* Would be quite nice if APR exported this */
/* apr:network_io/unix/sockaddr.c */
static int looks_like_ip(const char *ipstr)
{
    if (ap_strchr_c(ipstr, ':')) {
        /* definitely not a hostname; assume it is intended to be an IPv6 address */
        return 1;
    }

    /* simple IPv4 address string check */
    while ((*ipstr == '.') || apr_isdigit(*ipstr))
        ipstr++;
    return (*ipstr == '\0');
}

static apr_status_t set_cf_default_proxies(apr_pool_t *p, cloudflare_config_t *config)
{
     apr_status_t rv;
     cloudflare_proxymatch_t *match;
     int i;
     char **proxies = CF_DEFAULT_TRUSTED_PROXY;

     for (i=0; i<CF_DEFAULT_TRUSTED_PROXY_COUNT; i++) {
         char *ip = apr_pstrdup(p, proxies[i]);
         char *s = ap_strchr(ip, '/');

         if (s) {
             *s++ = '\0';
         }
         if (!config->proxymatch_ip) {
             config->proxymatch_ip = apr_array_make(p, 1, sizeof(*match));
         }

         match = (cloudflare_proxymatch_t *) apr_array_push(config->proxymatch_ip);
         rv = apr_ipsubnet_create(&match->ip, ip, s, p);
     }
     return rv;
}

static const char *proxies_set(cmd_parms *cmd, void *internal,
                               const char *arg)
{
    cloudflare_config_t *config = ap_get_module_config(cmd->server->module_config,
                                                       &cloudflare_module);
    cloudflare_proxymatch_t *match;
    apr_status_t rv;
    char *ip = apr_pstrdup(cmd->temp_pool, arg);
    char *s = ap_strchr(ip, '/');
    if (s)
        *s++ = '\0';

    if (!config->proxymatch_ip)
        config->proxymatch_ip = apr_array_make(cmd->pool, 1, sizeof(*match));
    match = (cloudflare_proxymatch_t *) apr_array_push(config->proxymatch_ip);
    match->internal = internal;

    if (looks_like_ip(ip)) {
        /* Note s may be null, that's fine (explicit host) */
        rv = apr_ipsubnet_create(&match->ip, ip, s, cmd->pool);
    }
    else
    {
        apr_sockaddr_t *temp_sa;

        if (s) {
            return apr_pstrcat(cmd->pool, "RemoteIP: Error parsing IP ", arg,
                               " the subnet /", s, " is invalid for ",
                               cmd->cmd->name, NULL);
        }

        rv = apr_sockaddr_info_get(&temp_sa,  ip, APR_UNSPEC, 0,
                                   APR_IPV4_ADDR_OK, cmd->temp_pool);
        while (rv == APR_SUCCESS)
        {
            apr_sockaddr_ip_get(&ip, temp_sa);
            rv = apr_ipsubnet_create(&match->ip, ip, NULL, cmd->pool);
            if (!(temp_sa = temp_sa->next))
                break;
            match = (cloudflare_proxymatch_t *)
                    apr_array_push(config->proxymatch_ip);
            match->internal = internal;
        }
    }

    if (rv != APR_SUCCESS) {
        char msgbuf[128];
        apr_strerror(rv, msgbuf, sizeof(msgbuf));
        return apr_pstrcat(cmd->pool, "RemoteIP: Error parsing IP ", arg,
                           " (", msgbuf, " error) for ", cmd->cmd->name, NULL);
    }

    return NULL;
}

static int cloudflare_modify_connection(request_rec *r)
{
    conn_rec *c = r->connection;
    cloudflare_config_t *config = (cloudflare_config_t *)
        ap_get_module_config(r->server->module_config, &cloudflare_module);

    cloudflare_conn_t *conn;
#ifdef REMOTEIP_OPTIMIZED
    apr_sockaddr_t temp_sa_buff;
    apr_sockaddr_t *temp_sa = &temp_sa_buff;
#else
    apr_sockaddr_t *temp_sa;
#endif
    apr_status_t rv;
    char *remote = (char *) apr_table_get(r->headers_in, config->header_name);
    char *proxy_ips = NULL;
    char *parse_remote;
    char *eos;
    unsigned char *addrbyte;
    void *internal = NULL;
    const char *cf_visitor_header = NULL;

    apr_pool_userdata_get((void*)&conn, "mod_cloudflare-conn", c->pool);

    cf_visitor_header = apr_table_get(r->headers_in, "CF-Visitor");
    if (cf_visitor_header != NULL) {
        if ((remote) && (strstr(cf_visitor_header, "https") != NULL)) {
            apr_table_t *e = r->subprocess_env;
            apr_table_addn(e, "HTTPS", "on");
        }
    }

    if (conn) {
        if (remote && (strcmp(remote, conn->prior_remote) == 0)) {
            /* TODO: Recycle r-> overrides from previous request
             */
            goto ditto_request_rec;
        }
        else {
            /* TODO: Revert connection from previous request
             */
#if AP_MODULE_MAGIC_AT_LEAST(20111130,0)
            c->client_addr = conn->orig_addr;
            c->client_ip = (char *) conn->orig_ip;
#else
            c->remote_addr = conn->orig_addr;
            c->remote_ip = (char *) conn->orig_ip;
#endif
        }
    }

    /* Deny requests that do not have a CloudFlareRemoteIPHeader set when
     * DenyAllButCloudFlare is set. Do not modify the request otherwise and
     * return early.
     */
    if (!remote) {
        if (config->deny_all) {
            return 403;
        }

        return OK;
    }

    remote = apr_pstrdup(r->pool, remote);

#if AP_MODULE_MAGIC_AT_LEAST(20111130,0)

#ifdef REMOTEIP_OPTIMIZED
    memcpy(temp_sa, c->client_addr, sizeof(*temp_sa));
    temp_sa->pool = r->pool;
#else
    temp_sa = c->client_addr;
#endif

#else

#ifdef REMOTEIP_OPTIMIZED
    memcpy(temp_sa, c->remote_addr, sizeof(*temp_sa));
    temp_sa->pool = r->pool;
#else
    temp_sa = c->remote_addr;
#endif

#endif

    while (remote) {

        /* verify c->client_addr is trusted if there is a trusted proxy list
         */
        if (config->proxymatch_ip) {
            int i;
            cloudflare_proxymatch_t *match;
            match = (cloudflare_proxymatch_t *)config->proxymatch_ip->elts;
            for (i = 0; i < config->proxymatch_ip->nelts; ++i) {
#if AP_MODULE_MAGIC_AT_LEAST(20111130,0)
                if (apr_ipsubnet_test(match[i].ip, c->client_addr)) {
                    internal = match[i].internal;
                    break;
                }
#else
                if (apr_ipsubnet_test(match[i].ip, c->remote_addr)) {
                    internal = match[i].internal;
                    break;
                }
#endif
            }
            if (i && i >= config->proxymatch_ip->nelts) {
                if (config->deny_all) {
                    return 403;
                } else {
                    break;
                }
            }
        }

        if ((parse_remote = strrchr(remote, ',')) == NULL) {
            parse_remote = remote;
            remote = NULL;
        }
        else {
            *(parse_remote++) = '\0';
        }

        while (*parse_remote == ' ')
            ++parse_remote;

        eos = parse_remote + strlen(parse_remote) - 1;
        while (eos >= parse_remote && *eos == ' ')
            *(eos--) = '\0';

        if (eos < parse_remote) {
            if (remote)
                *(remote + strlen(remote)) = ',';
            else
                remote = parse_remote;
            break;
        }

#ifdef REMOTEIP_OPTIMIZED
        /* Decode client_addr - sucks; apr_sockaddr_vars_set isn't 'public' */
        if (inet_pton(AF_INET, parse_remote,
                      &temp_sa->sa.sin.sin_addr) > 0) {
            apr_sockaddr_vars_set(temp_sa, APR_INET, temp_sa.port);
        }
#if APR_HAVE_IPV6
        else if (inet_pton(AF_INET6, parse_remote,
                           &temp_sa->sa.sin6.sin6_addr) > 0) {
            apr_sockaddr_vars_set(temp_sa, APR_INET6, temp_sa.port);
        }
#endif
        else {
            rv = apr_get_netos_error();
#else /* !REMOTEIP_OPTIMIZED */
        /* We map as IPv4 rather than IPv6 for equivilant host names
         * or IPV4OVERIPV6
         */
        rv = apr_sockaddr_info_get(&temp_sa,  parse_remote,
                                   APR_UNSPEC, temp_sa->port,
                                   APR_IPV4_ADDR_OK, r->pool);
        if (rv != APR_SUCCESS) {
#endif
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG,  rv, r,
                          "RemoteIP: Header %s value of %s cannot be parsed "
                          "as a client IP",
                          config->header_name, parse_remote);
            if (remote)
                *(remote + strlen(remote)) = ',';
            else
                remote = parse_remote;
            break;
        }

        addrbyte = (unsigned char *) &temp_sa->sa.sin.sin_addr;

        /* For intranet (Internal proxies) ignore all restrictions below */
        if (!internal
              && ((temp_sa->family == APR_INET
                   /* For internet (non-Internal proxies) deny all
                    * RFC3330 designated local/private subnets:
                    * 10.0.0.0/8   169.254.0.0/16  192.168.0.0/16
                    * 127.0.0.0/8  172.16.0.0/12
                    */
                      && (addrbyte[0] == 10
                       || addrbyte[0] == 127
                       || (addrbyte[0] == 169 && addrbyte[1] == 254)
                       || (addrbyte[0] == 172 && (addrbyte[1] & 0xf0) == 16)
                       || (addrbyte[0] == 192 && addrbyte[1] == 168)))
#if APR_HAVE_IPV6
               || (temp_sa->family == APR_INET6
                   /* For internet (non-Internal proxies) we translated
                    * IPv4-over-IPv6-mapped addresses as IPv4, above.
                    * Accept only Global Unicast 2000::/3 defined by RFC4291
                    */
                      && ((temp_sa->sa.sin6.sin6_addr.s6_addr[0] & 0xe0) != 0x20))
#endif
        )) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG,  rv, r,
                          "RemoteIP: Header %s value of %s appears to be "
                          "a private IP or nonsensical.  Ignored",
                          config->header_name, parse_remote);
            if (remote)
                *(remote + strlen(remote)) = ',';
            else
                remote = parse_remote;
            break;
        }

#if AP_MODULE_MAGIC_AT_LEAST(20111130,0)
        if (!conn) {
            conn = (cloudflare_conn_t *) apr_palloc(c->pool, sizeof(*conn));
            apr_pool_userdata_set(conn, "mod_cloudflare-conn", NULL, c->pool);
            conn->orig_addr = c->client_addr;
            conn->orig_ip = c->client_ip;
        }
        /* Set remote_ip string */
        if (!internal) {
            if (proxy_ips)
                proxy_ips = apr_pstrcat(r->pool, proxy_ips, ", ",
                                        c->client_ip, NULL);
            else
                proxy_ips = c->client_ip;
        }

        c->client_addr = temp_sa;
        apr_sockaddr_ip_get(&c->client_ip, c->client_addr);
    }

    /* Nothing happened? */
    if (!conn || (c->client_addr == conn->orig_addr))
        return OK;

    /* Fixups here, remote becomes the new Via header value, etc
     * In the heavy operations above we used request scope, to limit
     * conn pool memory growth on keepalives, so here we must scope
     * the final results to the connection pool lifetime.
     * To limit memory growth, we keep recycling the same buffer
     * for the final apr_sockaddr_t in the remoteip conn rec.
     */
    c->client_ip = apr_pstrdup(c->pool, c->client_ip);
    conn->proxied_ip = c->client_ip;

    r->useragent_ip = c->client_ip;
    r->useragent_addr = c->client_addr;

    memcpy(&conn->proxied_addr, temp_sa, sizeof(*temp_sa));
    conn->proxied_addr.pool = c->pool;
    c->client_addr = &conn->proxied_addr;
#else
        if (!conn) {
            conn = (cloudflare_conn_t *) apr_palloc(c->pool, sizeof(*conn));
            apr_pool_userdata_set(conn, "mod_cloudflare-conn", NULL, c->pool);
            conn->orig_addr = c->remote_addr;
            conn->orig_ip = c->remote_ip;
        }

        /* Set remote_ip string */
        if (!internal) {
            if (proxy_ips)
                proxy_ips = apr_pstrcat(r->pool, proxy_ips, ", ",
                                        c->remote_ip, NULL);
            else
                proxy_ips = c->remote_ip;
        }

        c->remote_addr = temp_sa;
        apr_sockaddr_ip_get(&c->remote_ip, c->remote_addr);
    }

    /* Nothing happened? */
    if (!conn || (c->remote_addr == conn->orig_addr))
        return OK;

    /* Fixups here, remote becomes the new Via header value, etc
     * In the heavy operations above we used request scope, to limit
     * conn pool memory growth on keepalives, so here we must scope
     * the final results to the connection pool lifetime.
     * To limit memory growth, we keep recycling the same buffer
     * for the final apr_sockaddr_t in the remoteip conn rec.
     */
    c->remote_ip = apr_pstrdup(c->pool, c->remote_ip);
    conn->proxied_ip = c->remote_ip;
    memcpy(&conn->proxied_addr, temp_sa, sizeof(*temp_sa));
    conn->proxied_addr.pool = c->pool;
    c->remote_addr = &conn->proxied_addr;
#endif

    if (remote)
        remote = apr_pstrdup(c->pool, remote);
    conn->proxied_remote = remote;
    conn->prior_remote = apr_pstrdup(c->pool, apr_table_get(r->headers_in,
                                                      config->header_name));
    if (proxy_ips)
        proxy_ips = apr_pstrdup(c->pool, proxy_ips);
    conn->proxy_ips = proxy_ips;

    /* Unset remote_host string DNS lookups */
    c->remote_host = NULL;
    c->remote_logname = NULL;

ditto_request_rec:

    if (conn->proxy_ips) {
        apr_table_setn(r->notes, "cloudflare-proxy-ip-list", conn->proxy_ips);
        if (config->proxies_header_name)
            apr_table_setn(r->headers_in, config->proxies_header_name,
                           conn->proxy_ips);
    }

    ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r,
                  conn->proxy_ips
                      ? "Using %s as client's IP by proxies %s"
                      : "Using %s as client's IP by internal proxies",
                  conn->proxied_ip, conn->proxy_ips);
    return OK;
}

static const command_rec cloudflare_cmds[] =
{
    AP_INIT_TAKE1("CloudFlareRemoteIPHeader", header_name_set, NULL, RSRC_CONF,
                  "Specifies a request header to trust as the client IP, "
                  "Overrides the default of CF-Connecting-IP"),
    AP_INIT_ITERATE("CloudFlareRemoteIPTrustedProxy", proxies_set, 0, RSRC_CONF,
                    "Specifies one or more proxies which are trusted "
                    "to present IP headers. Overrides the defaults."),
    AP_INIT_NO_ARGS("DenyAllButCloudFlare", deny_all_set, NULL, RSRC_CONF,
                    "Return a 403 status to all requests which do not originate from "
                    "a CloudFlareRemoteIPTrustedProxy."),
    { NULL }
};

static void register_hooks(apr_pool_t *p)
{
    // We need to run very early so as to not trip up mod_security.
    // Hence, this little trick, as mod_security runs at APR_HOOK_REALLY_FIRST.
    ap_hook_post_read_request(cloudflare_modify_connection, NULL, NULL, APR_HOOK_REALLY_FIRST - 10);
}

module AP_MODULE_DECLARE_DATA cloudflare_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                            /* create per-directory config structure */
    NULL,                            /* merge per-directory config structures */
    create_cloudflare_server_config, /* create per-server config structure */
    merge_cloudflare_server_config,  /* merge per-server config structures */
    cloudflare_cmds,                 /* command apr_table_t */
    register_hooks                   /* register hooks */
};
