use std::env;

const USAGE: &str = "\
BBBL-Core — a censorship circumvention client. It finds a way out of a filtered
network, opens an encrypted tunnel, and serves it as a local SOCKS5 proxy.

Usage:
  bbbl-core [OPTIONS]
  bbbl-core help              show this text

Run it with no options and it asks for what it needs: protocol, scan mode, IP
version. Every question has a flag, and every flag has an environment variable
of its own. Setting either one is what stops the question being asked, and a
flag beats a variable.

  bbbl-core                                   answer the questions as they come
  bbbl-core --masque --turbo -4               nothing asked, straight to work
  bbbl-core --wg --thorough --noize gfw       classic wireguard on a strict network
  bbbl-core --gool --wiw-outer 162.159.192.1:2408 --wiw-inner 188.114.96.1:2408
  bbbl-core --mim                             two masque hops, for a different exit

Connection:
  --bind <addr>            local SOCKS5 listen address (default 127.0.0.1:1819)
  --http-proxy <addr>      also expose an HTTP CONNECT proxy on this address
                           (off by default, e.g. 127.0.0.1:1820)
  --upstream <url>         dial out through a proxy already running here, e.g.
                           socks5://127.0.0.1:1080 or http://user:pass@host:8080;
                           tor and psiphon dial through it as well when no tunnel
                           carries them (tor takes a socks5 address only)
  --mark <n>               put this firewall mark (SO_MARK) on every socket bbbl-core
                           opens to the internet, e.g. 0xff, so a tun front end on
                           the same Linux router can let them past instead of
                           looping them back in (Linux and Android, needs root or
                           CAP_NET_ADMIN); a name is looked up outside the mark, so
                           without --upstream the calls to the WARP API take an IP
                           address only, see --api-address
  --exit-loc <spec>        refuse a tunnel whose exit country is not wanted, checked
                           through the finished tunnel before socks5 opens and again
                           every minute after: !IR,AZ,RU blocks those, DE,SE allows
                           only those. Off unless you pass this flag: without it
                           nothing is looked up and no tunnel is refused
  --exit-loc-secs <n>      how often to recheck the exit country (default 60)
  --stats                  log how much has gone up and down and how long the
                           tunnel has been up (off by default)
  --stats-secs <n>         how often to log that line (default 60)
  --quick-reconnect        auto-accept reconnecting with the last known working gateway
  --no-quick-reconnect     always scan fresh, ignore any saved last-connection gateway
  -4                       scan/connect over IPv4 only (default)
  -6                       scan/connect over IPv6 only
  --dual                   scan/connect over both IPv4 and IPv6
  --ip <v4|v6|both>        the same choice written out
  --peer <ip:port>         force a MASQUE/WireGuard peer, skip scanning
  --wg-peer <ip:port>      force a WireGuard peer (warp-in-warp outer), skip scanning

Protocol:
  --masque                 use MASQUE over QUIC/HTTP-3 (default)
  --wg, --wireguard, --warp
                           use classic WireGuard
  --gool, --wiw            use gool: a wireguard warp tunnel carried inside a
                           masque one. The wireguard hop is dialled from
                           inside warp, so cloudflare gives it another exit
                           than your own address would get. Its identity is
                           <masque config>-gool.toml: --register gool makes
                           it, and the tunnel registers one from inside warp
                           when there is none
  --gool-peer <ip:port>    the wireguard endpoint gool dials inside the tunnel
                           (default: the one its registration names, port 2408)
  --gool-classic           the older gool: wireguard tunneled in wireguard
  --mim, --masque-in-masque
                           use MASQUE-in-MASQUE: a masque tunnel carried inside
                           another one, which changes the address you come out
                           of the way gool does, on the same carrier for both
                           hops (HTTP/3 in HTTP/3, or --h2 for HTTP/2 in HTTP/2)
  --protocol <name>        masque | wg | gool | mim

Classic gool (WARP-in-WARP) endpoints:
  Naming any of these selects the classic gool. Both hops are found by the
  scan unless you name them here. The port is
  required: which port gets through is exactly what differs between networks,
  so none is assumed for you. Name one hop and the scan finds the other,
  keeping your address out of the sweep. The two hops must be different
  addresses, and naming one selects warp-in-warp on its own, so --gool
  alongside is optional.
  --wiw-outer <ip:port>    the outer hop, the one your network sees
  --wiw-inner <ip:port>    the inner hop, reached through the outer one
  --wiw-peers <out[,in]>   both hops in one value, or only the outer one
  --wiw-scan               scan for both, ignoring any endpoint left in the
                           environment

MASQUE-in-MASQUE endpoints:
  The outer hop is found by the scan and the inner one is picked for you, both
  unless you name them here. The port is required, and the two hops must be
  different addresses. Naming one selects masque-in-masque on its own.
  --mim-outer <ip:port>    the outer hop, the one your network sees
  --mim-inner <ip:port>    the inner hop, reached through the outer one
  --mim-peers <out[,in]>   both hops in one value, or only the outer one
  --mim-scan               find the outer hop by scanning, ignoring any endpoint
                           left in the environment

Scan mode:
  --scan <mode>            turbo | balanced | thorough | verified | ironclad
  --turbo                  stop at the first candidate that answers
  --balanced               default: collect a few, keep the fastest
  --thorough               sweep whole ranges, for when everything looks blocked
  --verified               dial only the edges measured to answer connect-ip,
                           never a guessed neighbour. On --gool and --mim it also
                           keeps the two hops in separate ranges, which is what
                           moves the exit address; the plain modes are untouched
  --ironclad               open a real tunnel and make a real HTTP request per
                           candidate, so a gateway is only trusted once it has
                           genuinely carried traffic

Obfuscation:
  --noize <profile>        off | light | firewall | balanced | gfw | aggressive
                           firewall is the default for MASQUE, balanced for
                           WireGuard and gool; reach for gfw when the default
                           does not get through

MASQUE transport:
  --h2, --http2            use HTTP/2 (TCP) instead of HTTP/3 (QUIC)
  --h3, --quic             use HTTP/3 (QUIC), without asking
  --no-quic-v2             do not send the QUIC v2 version-negotiation opener
                           (it is on by default; it opens a path for HTTP/3 on
                           networks that block QUIC v1 but let QUIC v2 through)
  --h2-peer <ip:port>      override the peer used for the HTTP/2 transport
  --no-data-check          skip the end-to-end data-plane validation
  --validate-secs <n>      seconds to wait for data-plane validation (default 10)
  --startup-secs <n>       total MASQUE startup deadline (default 30)
  --reconnect-secs <n>     delay before reconnecting after a tunnel drop (default 2)
  --dns <list>             resolvers used inside the tunnel (default 1.1.1.1,1.0.0.1)
  --fragment               fragment the TLS ClientHello on the HTTP/2 transport
                           and on the calls to the WARP API, whatever the
                           transport (off by default; it helps where a
                           firewall resets a whole ClientHello whose SNI ends
                           in cloudflareclient.com, as Iran's does)
  --fragment-size <n|a-b>  fragment chunk size in bytes (default 8-16)
  --fragment-delay <n|a-b> delay between fragments in ms (default 2-10)

TLS:
  the TLS handshakes of the tunnel and its setup, MASQUE over HTTP/2 and HTTP/3,
  the calls to the WARP API and the DoH lookup of --ech-dns, have Chrome's
  fingerprint as BoringSSL writes it, with what these change; certificates go
  unchecked
  --masque-sni <name>      the server name the MASQUE handshakes, over HTTP/3 and
                           HTTP/2, put in their ClientHello (default
                           www.cloudflare.com; the WARP client sends
                           consumer-masque.cloudflareclient.com); the HTTP host,
                           the :authority of the CONNECT request, stays
                           cloudflareaccess.com. With --ech it is the name
                           inside the encrypted ClientHello
  --ech <auto|base64>      enable Encrypted Client Hello on the MASQUE handshakes
                           and the calls to the WARP API, with the key looked up
                           (auto) or given in base64; without a key it can
                           offer, neither goes ahead rather than send a name in
                           the clear. The DoH lookup of the key goes without it
  --ech-dns <url>          the resolver --ech auto asks for the key:
                           udp://ip[:port] or tcp://ip[:port], port 53 unless
                           given, or a DNS-over-HTTPS https:// URL, port 443
                           unless given (default udp://1.1.1.1). After the URL,
                           @address=<ip|name> sends the connection there and
                           @sni=<name> puts that name in the ClientHello; the
                           URL's host stays the HTTP host, e.g.
                           https://doq.dns4all.eu/dns-query@address=2.2.2.2@sni=google.com
  --ech-domain <name>      the domain whose key --ech auto takes
                           (default cloudflare-ech.com)
  --tls-ciphers <list>     TLS 1.2 cipher suites, listed after the TLS 1.3 ones,
                           which stay as they are; names separated by ':', e.g.
                           \"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256\"
                           (default Chrome's, \"ALL:!aPSK:!ECDSA+SHA1:!3DES\").
                           HTTP/3 lists none: QUIC offers TLS 1.3 alone
  --tls-groups <list>      TLS groups, in order, the first with a key share
                           (default \"P-256:X25519:P-384\")
  --disable-grease         leave out the GREASE values (RFC 8701) the cipher
                           suites, extensions, groups, key shares and versions
                           carry by default, as Chrome's do

WireGuard:
  --keepalive <n>          persistent keepalive interval in seconds (default 5)
  --no-profile-retry       don't retry other obfuscation profiles during scan

Tor:
  Three ways to use tor, all needing a build made with the tor feature:
  cargo build --release --features tor

  --tor                    carry tor inside the tunnel: bbbl-core -> warp -> tor ->
                           internet. The usual proxy keeps the warp exit and a
                           second one, on --tor-bind, comes out of tor. Any
                           transport carries it, with nothing in between, so
                           --wg --tor has the wireguard tunnel carry tor itself
  --tor-reverse            the other way round: dial the tunnel through tor, so
                           warp is reached from a tor exit and your network never
                           sees warp. Tor carries tcp only and the wireguard
                           endpoints of warp answer on udp alone, so this runs
                           masque over http/2, gool's outer hop too, and
                           refuses --wg and --gool-classic
  --tor-only               no tunnel at all: the proxy on --bind is plain tor
  --tor-bind <addr>        where the tor proxy listens with --tor and
                           --tor-reverse (default 127.0.0.1:1820)
  --tor-http <addr>        also serve tor as an http/connect proxy here, for
                           clients that cannot speak socks5 (off by default)
  --tor-bridge-file <path> read bridge lines from this file, one per line, the
                           same shape torrc uses; blank lines and # are skipped
  --tor-relays <what>      running tor relays from onionoo, used as plain
                           bridges: auto (default, alongside bridgedb), only,
                           off, or a count such as 80. bridgedb hands out a
                           handful of bridges that are enumerated and blocked
                           early; onionoo lists every running relay, which is a
                           far larger pool to measure against
  --tor-relay-ports <set>  which relay ports to consider: web (default, only
                           80 and 443, the ports a restrictive firewall tends
                           to leave open) or any. the ports tor itself is known
                           for are always skipped
  --tor-dir <path>         where tor keeps its directory cache and state
                           (default <config>-tor beside the identity file)

  --psiphon                carry psiphon inside the tunnel: bbbl-core -> warp ->
                           psiphon -> internet, served on --psiphon-bind
  --psiphon-reverse        the other way round: dial the tunnel through psiphon.
                           psiphon carries tcp only, so this runs masque over
                           http/2, gool's outer hop too, and refuses --wg and
                           --gool-classic
  --psiphon-only           no tunnel at all: the proxy on --bind is plain psiphon
  --psiphon-mode <shape>   auto (default, let psiphon pick), cdn (only fronted
                           meek through a cdn, for networks that block the rest)
                           or direct (no fronting)
  --psiphon-config <path>  a psiphon json config of your own, laid over the
                           built-in one. only needed to use different
                           credentials or server list settings
  --psiphon-cdn-ips <list> addresses to try as cdn fronting edges, comma or
                           space separated. left empty, the list built into
                           psiphon is used
  --psiphon-cdn-sni <list> server names to present to those edges
  --psiphon-cdn-sets <list>
                           which of the edge lists built into psiphon the
                           fronting scan tries: cloudflare, fastly, cloudfront,
                           psiphon-akamai, psiphon-bunny, vercel, github,
                           curated-fronting, legacy-android-overrides. left
                           empty, all of them; named beside --psiphon-cdn-ips,
                           they are tried after those addresses
  --psiphon-bind <addr>    where the psiphon proxy listens with --psiphon and
                           --psiphon-reverse (default 127.0.0.1:1821)
  --psiphon-http <addr>    also serve psiphon as an http/connect proxy here
  --psiphon-region <cc>    ask psiphon to leave from this country, e.g. DE. the
                           log lists what is on offer as AvailableEgressRegions
  --psiphon-dir <path>     where psiphon keeps its data (default
                           <config>-psiphon beside the identity file)
  --psiphon-bin <path>     the psiphon-tunnel-core binary to run, when it is not
                           next to bbbl-core, in ./pt, or on PATH
  --psiphon-server-entries <path>
                           a file of server entries psiphon starts with, in the
                           form the remote list unpacks to, so that the first
                           connection does not depend on downloading that list;
                           a fetched list is merged on top of it

  On a network that blocks tor, bbbl-core fetches its own bridges from bridgedb and
  finds the pluggable transports already on this machine, tor browser's included.
  Nothing below is needed for that; it is there to override what it picks.

  --tor-bridges            go to bridges at once, without trying tor plainly first
  --no-tor-bridges         never use bridges, however blocked the network looks
  --tor-bridge <line>      a bridge line of your own, instead of the fetched ones.
                           Repeat it for more than one, e.g.
                           --tor-bridge \"obfs4 1.2.3.4:443 FINGERPRINT cert=... iat-mode=0\"
  --tor-pt [name=]<path>   the pluggable transport binary a bridge needs, e.g.
                           --tor-pt /usr/bin/lyrebird (obfs4 is assumed) or
                           --tor-pt snowflake=/usr/bin/snowflake-client
  --tor-pt-dir <path>      another folder to look in for those binaries

Zero Trust (WARP for organizations):
  --team <name>            enrol into a Zero Trust organization by team name
  --access-id <id>         service token client id (headless enrolment)
  --access-secret <secret> service token client secret (headless enrolment)
  --access-email <addr>    sign in with a one-time code emailed to this address
  --access-token <jwt>     an enrolment token you already obtained by signing in
                           at https://<team>.cloudflareaccess.com/warp
  --gateway                send http and https through the organization's gateway
                           proxy so its filtering and logging apply (off by default:
                           it adds a hop inside the tunnel and logs your browsing)

Routing (which traffic goes where):
  --route-block <list>     never let these reach the network at all
  --route-direct <list>    send these straight out, bypassing the tunnel
  --routes <path>          load both lists from a file with [block] and [direct]
                           sections
                           list entries are comma or newline separated and may be:
                             example.com          the name and every subdomain
                             full:example.com     that exact name only
                             keyword:doubleclick  any name containing it
                             regexp:^ad[0-9]+     a regular expression
                             10.0.0.0/8           a network, or a bare address
                             port:25              a port, or port:3000-3010
                             private              lan, loopback and cgnat space
                           block is checked first, then direct, otherwise the
                           tunnel is used

Config files:
  --config <path>          base identity config path (default bbbl-core.toml)
  --wg-config <path>       identity config path for WireGuard
  --masque-config <path>   identity config path for MASQUE
                           warp-in-warp adds a second identity of its own beside
                           the wireguard one, named <config>-secondary.toml
  --register <which>       register identities and exit, with no scan and no
                           tunnel: masque, wg, gool (masque and the wireguard
                           identity gool carries inside it, registered from
                           here rather than from inside warp), gool-classic
                           (both wireguard hops), mim (both masque hops) or all
                           five. Each new identity is saved only once WARP is
                           enabled on it. An identity file already
                           there is kept, never replaced; point the config paths
                           at new files to get new keys. With --tor-reverse or
                           --psiphon-reverse the registrations go through that
                           carrier whatever the protocol: they are https, which
                           tor and psiphon carry, so --wg and --gool-classic are
                           refused there only for the tunnel
  --api-address <ip|name[:port]>
                           where the calls to the WARP API, which register and
                           enroll the keys, go: port 443 unless one follows the
                           address, an IPv6 one then in brackets, e.g.
                           188.114.97.6:443 or [2606:4700::1]:8443 (default
                           api.cloudflareclient.com); the server name and the
                           HTTP host stay api.cloudflareclient.com. With --mark
                           and no --upstream, an IP address only

Advanced:
  --perf <low|medium|high> force a resource profile instead of auto-detecting from cpu/ram
                           (low: routers/small boards, medium: typical desktop, high: servers)
  --log-level <level>      error | warn | info | debug | trace (default info)
                           info: connection stages, validation, reconnects, retries
                           debug: adds per-tunnel internals useful for troubleshooting
                           trace: everything, including per-packet noise
  --verbose                shortcut for --log-level debug (RUST_LOG overrides both)

  -v, --version            show version and exit
  -h, --help, help         show this help and exit

Environment variables:
  Every flag above has one, for scripts and services. The last few have no flag
  of their own.

  BBBL-CORE_SOCKS                     --bind
  BBBL-CORE_HTTP_PROXY                --http-proxy
  BBBL-CORE_UPSTREAM                  --upstream
  BBBL-CORE_MARK                      --mark
  BBBL-CORE_STATS                     --stats
  BBBL-CORE_STATS_SECS                --stats-secs
  BBBL-CORE_EXIT_LOC                  --exit-loc
  BBBL-CORE_EXIT_LOC_SECS             --exit-loc-secs
  BBBL-CORE_TOR                       chain for --tor, reverse, or only
  BBBL-CORE_TOR_BRIDGES               --tor-bridge, several separated by ;
                                   auto for --tor-bridges, off for --no-tor-bridges
  BBBL-CORE_TOR_PT                    --tor-pt, several separated by ;
  BBBL-CORE_TOR_PT_DIR                --tor-pt-dir, several separated by ;
  BBBL-CORE_TOR_BIND                  --tor-bind
  BBBL-CORE_TOR_HTTP                  --tor-http
  BBBL-CORE_TOR_BRIDGE_FILE           --tor-bridge-file
  BBBL-CORE_TOR_RELAYS                --tor-relays
  BBBL-CORE_TOR_RELAY_PORTS           --tor-relay-ports
  BBBL-CORE_PSIPHON                   --psiphon (chain), --psiphon-reverse,
                                   --psiphon-only
  BBBL-CORE_PSIPHON_CONFIG            --psiphon-config
  BBBL-CORE_PSIPHON_MODE              --psiphon-mode
  BBBL-CORE_PSIPHON_CDN_IPS           --psiphon-cdn-ips
  BBBL-CORE_PSIPHON_CDN_SNI           --psiphon-cdn-sni
  BBBL-CORE_PSIPHON_CDN_SETS          --psiphon-cdn-sets
  BBBL-CORE_PSIPHON_BIND              --psiphon-bind
  BBBL-CORE_PSIPHON_HTTP              --psiphon-http
  BBBL-CORE_PSIPHON_REGION            --psiphon-region
  BBBL-CORE_PSIPHON_DIR               --psiphon-dir
  BBBL-CORE_PSIPHON_BIN               --psiphon-bin
  BBBL-CORE_PSIPHON_SERVER_ENTRIES    --psiphon-server-entries
  BBBL-CORE_PSIPHON_READY_SECS        how long to wait for psiphon to tunnel (180)
  BBBL-CORE_TOR_DIR                   --tor-dir
  BBBL-CORE_TOR_DIRECT_SECS           how long to try tor plainly before bridges (75)
  BBBL-CORE_TOR_STALL_SECS            give up on a bridge after this long with no
                                   headway, however far it got (75)
  BBBL-CORE_TOR_BRIDGE_SECS           the longest any one bridge may take (360)
  BBBL-CORE_TOR_COUNTRY               ask bridgedb for this country, e.g. ir
  BBBL-CORE_TOR_CHECK                 host:port tor must reach before it counts as
                                   working (check.torproject.org:443)
  BBBL-CORE_TOR_LOG                   how loud tor is: info, debug or trace
  BBBL-CORE_QUICK_RECONNECT           1 or 0, for --quick-reconnect
  BBBL-CORE_IP                        --ip: v4, v6 or both
  BBBL-CORE_PEER                      --peer
  BBBL-CORE_WG_PEER                   --wg-peer
  BBBL-CORE_PROTOCOL                  --protocol: masque, wg, gool or mim
  BBBL-CORE_GOOL_INNER                --gool-peer
  BBBL-CORE_GOOL_MODE                 classic for --gool-classic
  BBBL-CORE_WIW_OUTER_PEER            --wiw-outer
  BBBL-CORE_WIW_INNER_PEER            --wiw-inner
  BBBL-CORE_WIW_PEERS                 --wiw-peers, or auto for --wiw-scan
  BBBL-CORE_MIM_OUTER_PEER            --mim-outer
  BBBL-CORE_MIM_INNER_PEER            --mim-inner
  BBBL-CORE_MIM_PEERS                 --mim-peers, or auto for --mim-scan
  BBBL-CORE_SCAN                      --scan
  BBBL-CORE_NOIZE                     --noize
  BBBL-CORE_MASQUE_HTTP2              --h2 (1), or --h3 (0)
  BBBL-CORE_QUIC_V2                   0 for --no-quic-v2 (the opener is on by default)
  BBBL-CORE_MASQUE_H2_PEER            --h2-peer
  BBBL-CORE_MASQUE_NO_DATA_CHECK      --no-data-check, MASQUE side
  BBBL-CORE_WG_NO_DATA_CHECK          --no-data-check, WireGuard side
  BBBL-CORE_MASQUE_VALIDATE_SECS      --validate-secs, MASQUE side
  BBBL-CORE_WG_VALIDATE_SECS          --validate-secs, WireGuard side
  BBBL-CORE_MASQUE_STARTUP_SECS       --startup-secs
  BBBL-CORE_MASQUE_RECONNECT_SECS     --reconnect-secs, MASQUE side
  BBBL-CORE_WG_RECONNECT_SECS         --reconnect-secs, WireGuard side
  BBBL-CORE_DNS                       --dns
  BBBL-CORE_MASQUE_H2_FRAGMENT        --fragment (default off)
  BBBL-CORE_MASQUE_H2_FRAGMENT_SIZE   --fragment-size
  BBBL-CORE_MASQUE_H2_FRAGMENT_DELAY  --fragment-delay
  BBBL-CORE_MASQUE_SNI                --masque-sni
  BBBL-CORE_ECH                       --ech
  BBBL-CORE_ECH_DNS                   --ech-dns
  BBBL-CORE_ECH_DOMAIN                --ech-domain
  BBBL-CORE_TLS_CIPHERS               --tls-ciphers
  BBBL-CORE_TLS_GROUPS                --tls-groups
  BBBL-CORE_DISABLE_GREASE            --disable-grease
  BBBL-CORE_WG_KEEPALIVE              --keepalive
  BBBL-CORE_WG_NO_PROFILE_RETRY       --no-profile-retry
  BBBL-CORE_TEAM                      --team
  BBBL-CORE_ACCESS_CLIENT_ID          --access-id
  BBBL-CORE_ACCESS_CLIENT_SECRET      --access-secret
  BBBL-CORE_ACCESS_TOKEN              --access-token
  BBBL-CORE_ACCESS_EMAIL              --access-email
  BBBL-CORE_GATEWAY                   --gateway
  BBBL-CORE_ROUTE_BLOCK               --route-block
  BBBL-CORE_ROUTE_DIRECT              --route-direct
  BBBL-CORE_ROUTES_FILE               --routes
  BBBL-CORE_CONFIG                    --config
  BBBL-CORE_WG_CONFIG                 --wg-config
  BBBL-CORE_MASQUE_CONFIG             --masque-config
  BBBL-CORE_REGISTER                  --register
  BBBL-CORE_API_ADDRESS               --api-address
  BBBL-CORE_PERF_PROFILE              --perf
  BBBL-CORE_LOG_LEVEL                 --log-level

  BBBL-CORE_ROUTE_SNIFF               0 to stop reading the server name from the
                                   first bytes of a connection (on by default,
                                   which is what makes routing rules work behind
                                   a tun front end)
  BBBL-CORE_ROUTE_SNIFF_MS            how long to wait for those bytes (default 400)
  BBBL-CORE_WG_ENDPOINT_COOLDOWN_SECS how long an endpoint is left out of rescans once
                                   its tunnel ended twice in a row, each time within
                                   five minutes of starting (default 300)
  BBBL-CORE_WG_STALE_SECS             silence on a wireguard tunnel before it counts
                                   as dead (default 10)
  BBBL-CORE_MASQUE_H2_KEEPALIVE_SECS  HTTP/2 keepalive interval (default 15)
  BBBL-CORE_MASQUE_H2_KEEPALIVE_TIMEOUT_SECS
                                   how long a keepalive may go unanswered (default 20)
  BBBL-CORE_IRONCLAD_PORT             port the ironclad scan makes its real HTTP
                                   request to (default 80)
  BBBL-CORE_MAX_CLIENTS               proxy clients served at once; past it new ones
                                   wait for a free slot (default by resources,
                                   512 to 8192)
  BBBL-CORE_HALF_CLOSE_SECS           how long a connection the client has finished
                                   sending on may sit silent before it is closed
                                   (default 30)
  BBBL-CORE_TCP_KEEPALIVE_SECS        idle time before a keep-alive checks that the
                                   other end of a connection is still there;
                                   three unanswered ones close it (default 60)
  BBBL-CORE_TCP_CONNECT_SECS          how long a connection through the tunnel may
                                   take to open (default 30)
  BBBL-CORE_REPROVISION               0 to stop replacing an identity Cloudflare has
                                   refused with a freshly registered one
  RUST_LOG                         standard rust log filter; overrides --log-level

After startup the proxy is at the address --bind names, 127.0.0.1:1819 by
default. Check it with:

  curl -x socks5h://127.0.0.1:1819 https://www.cloudflare.com/cdn-cgi/trace

The reply should show a Cloudflare colo and warp=on. The proxy has no
authentication, so bind it to 0.0.0.0 only when you mean to share the tunnel
with your network.
";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parsed {
    Run,
    Done,
}

pub fn parse_and_apply() -> crate::error::Result<Parsed> {
    parse_args(env::args().skip(1).collect())
}

pub fn parse_args(args: Vec<String>) -> crate::error::Result<Parsed> {
    let mut i = 0;

    while i < args.len() {
        let arg = args[i].as_str();

        macro_rules! next_value {
            () => {{
                i += 1;
                args.get(i).ok_or_else(|| {
                    crate::error::BBBL-CoreError::Other(format!("{arg} requires a value"))
                })?
            }};
        }

        match arg {
            "-v" | "--version" => {
                println!("bbbl-core {}", env!("CARGO_PKG_VERSION"));
                return Ok(Parsed::Done);
            }

            "-h" | "--help" | "help" => {
                print!("{USAGE}");
                return Ok(Parsed::Done);
            }

            "--bind" => set("BBBL-CORE_SOCKS", next_value!()),
            "--http-proxy" => set("BBBL-CORE_HTTP_PROXY", next_value!()),
            "--upstream" => set("BBBL-CORE_UPSTREAM", next_value!()),
            "--tor" => set("BBBL-CORE_TOR", "chain"),
            "--tor-reverse" => set("BBBL-CORE_TOR", "reverse"),
            "--tor-only" => set("BBBL-CORE_TOR", "only"),
            "--tor-bridge" => append("BBBL-CORE_TOR_BRIDGES", next_value!()),
            "--tor-bridges" => set("BBBL-CORE_TOR_BRIDGES", "auto"),
            "--tor-bridge-file" => set("BBBL-CORE_TOR_BRIDGE_FILE", next_value!()),
            "--tor-relays" => set("BBBL-CORE_TOR_RELAYS", next_value!()),
            "--tor-relay-ports" => set("BBBL-CORE_TOR_RELAY_PORTS", next_value!()),
            "--no-tor-bridges" => set("BBBL-CORE_TOR_BRIDGES", "off"),
            "--tor-pt" => append("BBBL-CORE_TOR_PT", next_value!()),
            "--tor-pt-dir" => append("BBBL-CORE_TOR_PT_DIR", next_value!()),
            "--tor-bind" => set("BBBL-CORE_TOR_BIND", next_value!()),
            "--tor-http" => set("BBBL-CORE_TOR_HTTP", next_value!()),
            "--tor-dir" => set("BBBL-CORE_TOR_DIR", next_value!()),
            "--psiphon" => set("BBBL-CORE_PSIPHON", "chain"),
            "--psiphon-reverse" => set("BBBL-CORE_PSIPHON", "reverse"),
            "--psiphon-only" => set("BBBL-CORE_PSIPHON", "only"),
            "--psiphon-config" => set("BBBL-CORE_PSIPHON_CONFIG", next_value!()),
            "--psiphon-bind" => set("BBBL-CORE_PSIPHON_BIND", next_value!()),
            "--psiphon-http" => set("BBBL-CORE_PSIPHON_HTTP", next_value!()),
            "--psiphon-region" => set("BBBL-CORE_PSIPHON_REGION", next_value!()),
            "--psiphon-mode" => set("BBBL-CORE_PSIPHON_MODE", next_value!()),
            "--psiphon-cdn-ips" => set("BBBL-CORE_PSIPHON_CDN_IPS", next_value!()),
            "--psiphon-cdn-sni" => set("BBBL-CORE_PSIPHON_CDN_SNI", next_value!()),
            "--psiphon-cdn-sets" => set("BBBL-CORE_PSIPHON_CDN_SETS", next_value!()),
            "--psiphon-dir" => set("BBBL-CORE_PSIPHON_DIR", next_value!()),
            "--psiphon-bin" => set("BBBL-CORE_PSIPHON_BIN", next_value!()),
            "--psiphon-server-entries" => set("BBBL-CORE_PSIPHON_SERVER_ENTRIES", next_value!()),
            "--mark" => set("BBBL-CORE_MARK", next_value!()),
            "--exit-loc" => set("BBBL-CORE_EXIT_LOC", next_value!()),
            "--exit-loc-secs" => set("BBBL-CORE_EXIT_LOC_SECS", next_value!()),
            "--stats" => set("BBBL-CORE_STATS", "1"),
            "--stats-secs" => set("BBBL-CORE_STATS_SECS", next_value!()),
            "--quick-reconnect" => set("BBBL-CORE_QUICK_RECONNECT", "1"),
            "--no-quick-reconnect" => set("BBBL-CORE_QUICK_RECONNECT", "0"),

            "-4" => set("BBBL-CORE_IP", "v4"),
            "-6" => set("BBBL-CORE_IP", "v6"),
            "--dual" => set("BBBL-CORE_IP", "both"),
            "--ip" => set("BBBL-CORE_IP", next_value!()),

            "--peer" => set("BBBL-CORE_PEER", next_value!()),
            "--wg-peer" => set("BBBL-CORE_WG_PEER", next_value!()),

            "--wiw-outer" | "--gool-outer" | "--outer-peer" => {
                set("BBBL-CORE_WIW_OUTER_PEER", next_value!())
            }
            "--wiw-inner" | "--gool-inner" | "--inner-peer" => {
                set("BBBL-CORE_WIW_INNER_PEER", next_value!())
            }
            "--wiw-peers" | "--gool-peers" => set("BBBL-CORE_WIW_PEERS", next_value!()),
            "--wiw-scan" | "--gool-scan" => set("BBBL-CORE_WIW_PEERS", "auto"),

            "--masque" => set("BBBL-CORE_PROTOCOL", "masque"),
            "--wg" | "--wireguard" | "--warp" => set("BBBL-CORE_PROTOCOL", "wg"),
            "--gool" | "--wiw" => set("BBBL-CORE_PROTOCOL", "gool"),
            "--gool-peer" => {
                set("BBBL-CORE_PROTOCOL", "gool");
                set("BBBL-CORE_GOOL_INNER", next_value!())
            }
            "--gool-classic" => {
                set("BBBL-CORE_PROTOCOL", "gool");
                set("BBBL-CORE_GOOL_MODE", "classic")
            }
            "--mim" | "--masque-in-masque" => set("BBBL-CORE_PROTOCOL", "mim"),
            "--mim-outer" => set("BBBL-CORE_MIM_OUTER_PEER", next_value!()),
            "--mim-inner" => set("BBBL-CORE_MIM_INNER_PEER", next_value!()),
            "--mim-peers" => set("BBBL-CORE_MIM_PEERS", next_value!()),
            "--mim-scan" => set("BBBL-CORE_MIM_PEERS", "auto"),
            "--protocol" => set("BBBL-CORE_PROTOCOL", next_value!()),

            "--scan" => set("BBBL-CORE_SCAN", next_value!()),
            "--turbo" => set("BBBL-CORE_SCAN", "turbo"),
            "--balanced" => set("BBBL-CORE_SCAN", "balanced"),
            "--thorough" => set("BBBL-CORE_SCAN", "thorough"),
            "--verified" | "--stealth" => set("BBBL-CORE_SCAN", "verified"),
            "--ironclad" => set("BBBL-CORE_SCAN", "ironclad"),

            "--noize" => set("BBBL-CORE_NOIZE", next_value!()),

            "--h2" | "--http2" => set("BBBL-CORE_MASQUE_HTTP2", "1"),
            "--h3" | "--quic" => set("BBBL-CORE_MASQUE_HTTP2", "0"),
            "--no-quic-v2" => set("BBBL-CORE_QUIC_V2", "0"),
            "--h2-peer" => set("BBBL-CORE_MASQUE_H2_PEER", next_value!()),
            "--masque-sni" => set("BBBL-CORE_MASQUE_SNI", next_value!()),
            "--ech" => set("BBBL-CORE_ECH", next_value!()),
            "--ech-dns" => set("BBBL-CORE_ECH_DNS", next_value!()),
            "--ech-domain" => set("BBBL-CORE_ECH_DOMAIN", next_value!()),
            "--no-data-check" => {
                set("BBBL-CORE_MASQUE_NO_DATA_CHECK", "1");
                set("BBBL-CORE_WG_NO_DATA_CHECK", "1");
            }
            "--validate-secs" => {
                let value = next_value!().clone();
                set("BBBL-CORE_MASQUE_VALIDATE_SECS", &value);
                set("BBBL-CORE_WG_VALIDATE_SECS", &value);
            }
            "--startup-secs" => set("BBBL-CORE_MASQUE_STARTUP_SECS", next_value!()),
            "--reconnect-secs" => {
                let value = next_value!().clone();
                set("BBBL-CORE_MASQUE_RECONNECT_SECS", &value);
                set("BBBL-CORE_WG_RECONNECT_SECS", &value);
            }
            "--dns" => set("BBBL-CORE_DNS", next_value!()),
            "--fragment" => set("BBBL-CORE_MASQUE_H2_FRAGMENT", "1"),
            "--fragment-size" => set("BBBL-CORE_MASQUE_H2_FRAGMENT_SIZE", next_value!()),
            "--fragment-delay" => set("BBBL-CORE_MASQUE_H2_FRAGMENT_DELAY", next_value!()),

            "--keepalive" => set("BBBL-CORE_WG_KEEPALIVE", next_value!()),
            "--no-profile-retry" => set("BBBL-CORE_WG_NO_PROFILE_RETRY", "1"),

            "--config" => set("BBBL-CORE_CONFIG", next_value!()),
            "--wg-config" => set("BBBL-CORE_WG_CONFIG", next_value!()),
            "--masque-config" => set("BBBL-CORE_MASQUE_CONFIG", next_value!()),
            "--register" => set("BBBL-CORE_REGISTER", next_value!()),
            "--api-address" => set("BBBL-CORE_API_ADDRESS", next_value!()),

            "--team" | "--organization" => set("BBBL-CORE_TEAM", next_value!()),
            "--access-id" => set("BBBL-CORE_ACCESS_CLIENT_ID", next_value!()),
            "--access-secret" => set("BBBL-CORE_ACCESS_CLIENT_SECRET", next_value!()),
            "--access-token" => set("BBBL-CORE_ACCESS_TOKEN", next_value!()),
            "--access-email" => set("BBBL-CORE_ACCESS_EMAIL", next_value!()),
            "--gateway" => set("BBBL-CORE_GATEWAY", "1"),

            "--route-block" => set("BBBL-CORE_ROUTE_BLOCK", next_value!()),
            "--route-direct" => set("BBBL-CORE_ROUTE_DIRECT", next_value!()),
            "--routes" => set("BBBL-CORE_ROUTES_FILE", next_value!()),

            "--tls-groups" => set("BBBL-CORE_TLS_GROUPS", next_value!()),
            "--tls-ciphers" => set("BBBL-CORE_TLS_CIPHERS", next_value!()),
            "--disable-grease" => set("BBBL-CORE_DISABLE_GREASE", "1"),
            "--tls-verify" => set("BBBL-CORE_TLS_VERIFY", "1"),
            "--perf" => set("BBBL-CORE_PERF_PROFILE", next_value!()),
            "--log-level" => set("BBBL-CORE_LOG_LEVEL", next_value!()),
            "--verbose" => set("BBBL-CORE_LOG_LEVEL", "debug"),

            other => {
                return Err(crate::error::BBBL-CoreError::Other(format!(
                    "unknown option '{other}'\n\n{USAGE}"
                )));
            }
        }

        i += 1;
    }

    Ok(Parsed::Run)
}

fn set(key: &str, value: &str) {
    std::env::set_var(key, value);
}

fn append(key: &str, value: &str) {
    match std::env::var(key) {
        Ok(existing) if !existing.trim().is_empty() => {
            std::env::set_var(key, format!("{existing};{value}"))
        }
        _ => std::env::set_var(key, value),
    }
}
