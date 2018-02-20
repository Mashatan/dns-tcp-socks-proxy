/*
 *  UDP-TCP SOCKS DNS Tunnel
 *  (C) 2012 jtRIPper
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 1, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/


#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <regex.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>
#include <errno.h>

#ifdef UNUSED
#elif defined(__GNUC__)
# define UNUSED(x) UNUSED_ ## x __attribute__((unused))
#elif defined(__LCLINT__)
# define UNUSED(x) /*@unused@*/ x
#else
# define UNUSED(x) x
#endif

struct DNS_HEADER
{
    unsigned short id; // identification number

    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag

    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available

    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};

// Constant sized fields of query structure
struct QUESTION
{
    unsigned short qtype;
    unsigned short qclass;
};

// Constant sized fields of the resource record structure
struct ANSWER
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};

// Pointers to resource record contents
struct RES_RECORD
{
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
};

// Structure of a Query
struct QUERY
{
    unsigned char *name;
    struct QUESTION *ques;
};


// Types of DNS resource records
#define T_A 1 //Ipv4 address
#define T_NS 2 //Nameserver
#define T_CNAME 5 //canonical name
#define T_SOA 6 //start of authority zone
#define T_PTR 12 //domain name pointer
#define T_MX 15 //Mail server

int   DNS_MODE = 0;
int   SOCKS_PORT  = 9050;
char *SOCKS_ADDR  = { "127.0.0.1" };
int   LISTEN_PORT = 53;
char *LISTEN_ADDR = { "0.0.0.0" };

FILE *LOG_FILE;
char *RESOLVCONF = "resolv.conf";
char *LOGFILE = "/dev/null";
char *USERNAME = "nobody";
char *GROUPNAME = "nobody";
int NUM_DNS = 0;
int LOG = 0;
char **dns_servers;

typedef struct {
  char *buffer;
  int length;
} response;

void error(char *e) {
  perror(e);
  exit(1);
}

char *get_value(char *line) {
  char *token, *tmp;
  token = strtok(line, " ");
  for (;;) {
    if ((tmp = strtok(NULL, " ")) == NULL)
      break;
    else
      token = tmp;
  }
  return token;
}

char *string_value(char *value) {
  char *tmp = (char*)malloc(strlen(value)+1);
  strcpy(tmp, value);
  value = tmp;
  if (value[strlen(value)-1] == '\n')
    value[strlen(value)-1] = '\0';
  return value;
}

void parse_config(char *file) {
  char line[80];

  FILE *f = fopen(file, "r");
  if (!f)
    error("[!] Error opening configuration file");

  while (fgets(line, 80, f) != NULL) {
    if (line[0] == '#')
      continue;

    if(strstr(line, "dns_mode") != NULL) {
      DNS_MODE = strtol(get_value(line), NULL, 10);
      printf("DNS_MODE = %d\n", DNS_MODE);
    }
    if(strstr(line, "socks_port") != NULL) 
      SOCKS_PORT = strtol(get_value(line), NULL, 10);
    else if(strstr(line, "socks_addr") != NULL)
      SOCKS_ADDR = string_value(get_value(line));
    else if(strstr(line, "listen_addr") != NULL)
      LISTEN_ADDR = string_value(get_value(line));
    else if(strstr(line, "listen_port") != NULL)
      LISTEN_PORT = strtol(get_value(line), NULL, 10);
    else if(strstr(line, "set_user") != NULL)
      USERNAME = string_value(get_value(line));
    else if(strstr(line, "set_group") != NULL)
      GROUPNAME = string_value(get_value(line));
    else if(strstr(line, "resolv_conf") != NULL)
      RESOLVCONF = string_value(get_value(line));
    else if(strstr(line, "log_file") != NULL)
      LOGFILE = string_value(get_value(line));
  }
  if (fclose(f) != 0)
	  error("[!] Error closing configuration file");
}

void parse_resolv_conf() {
  char ns[80];
  int i = 0;
  regex_t preg;
  regmatch_t pmatch[1];
  regcomp(&preg, "^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+\n$", REG_EXTENDED);

  FILE *f = fopen(RESOLVCONF, "r");
  if (!f)
    error("[!] Error opening resolv.conf");

  while (fgets(ns, 80, f) != NULL) {
    if (!regexec(&preg, ns, 1, pmatch, 0))
      NUM_DNS++;
  }

  if (fclose(f))
    error("[!] Error closing resolv.conf");
  
  dns_servers = malloc(sizeof(char*) * NUM_DNS);

  f = fopen(RESOLVCONF, "r");
  while (fgets(ns, 80, f) != NULL) {
    if (regexec(&preg, ns, 1, pmatch, 0) != 0)
      continue;
    dns_servers[i] = (char*)malloc(strlen(ns) + 1);
    strcpy(dns_servers[i], ns);
    i++;
  }
  if (fclose(f))
    error("[!] Error closing resolv.conf");
}



// handle children
void reaper_handle (int UNUSED(sig)) {
  while (waitpid(-1, NULL, WNOHANG) > 0) { };
}


void local_dns() {
  
}


void tcp_query(void *query, response *buffer, int len) {
  int sock;
  struct sockaddr_in tcp_dns_server;
  //char tmp[1024];

  srand(time(NULL));
  int idx = rand() % NUM_DNS;
  in_addr_t remote_dns = inet_addr(dns_servers[idx]);
  memset(&tcp_dns_server, 0, sizeof(tcp_dns_server));
  tcp_dns_server.sin_family = AF_INET;
  tcp_dns_server.sin_port = htons(53);
  tcp_dns_server.sin_addr.s_addr = remote_dns;

  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) 
    error("[!] Error creating TCP socket");


  if (connect(sock, (struct sockaddr*)&tcp_dns_server, sizeof(tcp_dns_server)) < 0)
    error("[!] Error connecting to proxy");
  // forward dns query
  send(sock, query, len, 0);
  buffer->length = recv(sock, buffer->buffer, 2048, 0);

}

void tcp_socks_query(void *query, response *buffer, int len) {
  int sock;
  struct sockaddr_in socks_server;
  char tmp[1024];

  memset(&socks_server, 0, sizeof(socks_server));
  socks_server.sin_family = AF_INET;
  socks_server.sin_port = htons(SOCKS_PORT);
  socks_server.sin_addr.s_addr = inet_addr(SOCKS_ADDR);

  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) 
    error("[!] Error creating TCP socket");

  if (connect(sock, (struct sockaddr*)&socks_server, sizeof(socks_server)) < 0)
    error("[!] Error connecting to proxy");
  
  // socks handshake
  send(sock, "\x05\x01\x00", 3, 0);
  recv(sock, tmp, 1024, 0);

  srand(time(NULL));

  // select random dns server
  int idx = rand() % NUM_DNS;
  in_addr_t remote_dns = inet_addr(dns_servers[idx]);
  memcpy(tmp, "\x05\x01\x00\x01", 4);
  memcpy(tmp + 4, &remote_dns, 4);
  memcpy(tmp + 8, "\x00\x35", 2);

  if (LOG == 1) { fprintf(LOG_FILE, "Using DNS server: %s\n", inet_ntoa(*(struct in_addr *)&remote_dns)); }

  send(sock, tmp, 10, 0);
  recv(sock, tmp, 1024, 0);

  // forward dns query
  send(sock, query, len, 0);
  buffer->length = recv(sock, buffer->buffer, 2048, 0);
}

int udp_listener() {
  int sock;
  char len, *query;
  response *buffer = (response*)malloc(sizeof(response));
  struct sockaddr_in dns_listener, dns_client;

  buffer->buffer = malloc(2048);

  memset(&dns_listener, 0, sizeof(dns_listener));
  dns_listener.sin_family = AF_INET;
  dns_listener.sin_port = htons(LISTEN_PORT);
  dns_listener.sin_addr.s_addr = inet_addr(LISTEN_ADDR);

  // create our udp listener
  sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0)
    error("[!] Error setting up dns proxy");

  if(bind(sock, (struct sockaddr*)&dns_listener, sizeof(dns_listener)) < 0)
    error("[!] Error binding on dns proxy");

  FILE *resolv = fopen("/etc/resolv.conf", "w");

  if (!resolv)
    error("[!] Error opening /etc/resolv.conf");

  fprintf(resolv, "nameserver %s\n", LISTEN_ADDR);
  fclose(resolv);

  if (strcmp(LOGFILE, "/dev/null") != 0) {
    LOG      = 1;
    LOG_FILE = fopen(LOGFILE, "a+");
    if (!LOG_FILE)
      error("[!] Error opening logfile.");
  }

  printf("[*] No errors, backgrounding process.\n");

  // daemonize the process.
  if(fork() != 0) { exit(0); }
  if(fork() != 0) { exit(0); }

  setuid(getpwnam(USERNAME)->pw_uid);
  setgid(getgrnam(GROUPNAME)->gr_gid);
  socklen_t dns_client_size = sizeof(struct sockaddr_in);

  // setup SIGCHLD handler to kill off zombie children
  struct sigaction reaper;
  memset(&reaper, 0, sizeof(struct sigaction));
  reaper.sa_handler = reaper_handle;
  sigaction(SIGCHLD, &reaper, 0);

  while(1) {
    // receive a dns request from the client
    len = recvfrom(sock, buffer->buffer, 2048, 0, (struct sockaddr *)&dns_client, &dns_client_size);

    // lets not fork if recvfrom was interrupted
    if (len < 0 && errno == EINTR) { continue; }

    // other invalid values from recvfrom
    if (len < 0) {
      if (LOG == 1) { fprintf(LOG_FILE, "recvfrom failed: %s\n", strerror(errno)); }
      continue;
    }

    // fork so we can keep receiving requests
    if (fork() != 0) { continue; }

    // the tcp query requires the length to precede the packet, so we put the length there
    query = malloc(len + 3);
    query[0] = 0;
    query[1] = len;
    memcpy(query + 2, buffer->buffer, len);

    // forward the packet to the tcp dns server
    if (DNS_MODE)
      tcp_socks_query(query, buffer, len + 2);
    else
      tcp_query(query, buffer, len + 2);

    // send the reply back to the client (minus the length at the beginning)
    sendto(sock, buffer->buffer + 2, buffer->length - 2, 0, (struct sockaddr *)&dns_client, sizeof(dns_client));

    free(buffer->buffer);
    free(buffer);
    free(query);

    exit(0);
  }
}

int main(int argc, char *argv[]) {
  if (argc == 1)
    parse_config("dns_proxy.conf");
  else if (argc == 2) {
    if (!strcmp(argv[1], "-h")) {
      printf("Usage: %s [options]\n", argv[0]);
      printf(" * With no parameters, the configuration file is read from 'dns_proxy.conf'.\n\n");
      printf(" -n          -- No configuration file (socks: 127.0.0.1:9999, listener: 0.0.0.0:53).\n");
      printf(" -h          -- Print this message and exit.\n");
      printf(" config_file -- Read from specified configuration file.\n\n");
      printf(" * The configuration file should contain any of the following options (and ignores lines that begin with '#'):\n");
      printf("   * dns_mode  -- choose dns mode (0=tcp or 1=socks)\n");
      printf("   * socks_addr  -- socks listener address\n");
      printf("   * socks_port  -- socks listener port\n");
      printf("   * listen_addr -- address for the dns proxy to listen on\n");
      printf("   * listen_port -- port for the dns proxy to listen on (most cases 53)\n");
      printf("   * set_user    -- username to drop to after binding\n");
      printf("   * set_group   -- group to drop to after binding\n");
      printf("   * resolv_conf -- location of resolv.conf to read from\n");
      printf("   * log_file    -- location to log server IPs to. (only necessary for debugging)\n\n");
      printf(" * Configuration directives should be of the format:\n");
      printf("   option = value\n\n");
      printf(" * Any non-specified options will be set to their defaults:\n");
      printf("   * dns_mode   = 0\n");
      printf("   * socks_addr   = 127.0.0.1\n");
      printf("   * socks_port   = 9050\n");
      printf("   * listen_addr  = 0.0.0.0\n");
      printf("   * listen_port  = 53\n");
      printf("   * set_user     = nobody\n");
      printf("   * set_group    = nobody\n");
      printf("   * resolv_conf  = resolv.conf\n");
      printf("   * log_file     = /dev/null\n");
      exit(0);
    }
    else {
      parse_config(argv[1]);
    }
  }

  if (getuid() != 0) {
    printf("Error: this program must be run as root! Quitting\n");
    exit(1);
  }

  printf("[*] Listening on: %s:%d\n", LISTEN_ADDR, LISTEN_PORT);
  printf("[*] DNS Mode: %s\n",  DNS_MODE==0? "TCP":"SOCKS");
  printf("[*] Using SOCKS proxy: %s:%d\n", SOCKS_ADDR, SOCKS_PORT);
  printf("[*] Will drop priviledges to %s:%s\n", USERNAME, GROUPNAME);
  parse_resolv_conf();
  printf("[*] Loaded %d DNS servers from %s.\n\n", NUM_DNS, RESOLVCONF);

  if (!getpwnam(USERNAME)) {
    printf("[!] Username (%s) does not exist! Quiting\n", USERNAME);
    exit(1);
  }
  if (!getgrnam(GROUPNAME)) {
    printf("[!] Group (%s) does not exist! Quiting\n", GROUPNAME);
    exit(1);
  }

  // start the dns proxy
  udp_listener();
  exit(EXIT_SUCCESS);
}
