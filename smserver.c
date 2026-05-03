#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <stdarg.h>

#define MAX_USERS 100
#define MAX_CLIENTS FD_SETSIZE
#define MAX_LINE 2048
#define MAX_RECIPIENTS 100
#define BODY_LIMIT 65536
#define BACKLOG 16
#define MODE_TIMEOUT_SECONDS 30

typedef struct{
    char username[21];
    char password[31];
    int next_id;
} User;

typedef enum{MODE_NONE = 0, MODE_SEND, MODE_RECV} Mode;

typedef enum{SMTP_WAIT_FROM = 0, SMTP_WAIT_TO_OR_SUB, SMTP_WAIT_BODY_CMD, SMTP_READING_BODY} SmtpState;

typedef struct{
    int active;
    int fd;
    struct sockaddr_in addr;
    time_t connected_at;
    Mode mode;

    char inbuf[MAX_LINE + 1];
    int inbuf_len;
    int line_too_long;

    SmtpState smtp_state;
    char sender[256];
    char subject[256];
    char recipients[MAX_RECIPIENTS][21];
    int recipient_count;
    char body[BODY_LIMIT + 1];
    int body_len;
    int body_too_large;

    char nonce[9];
    int auth_attempts;
    int auth_user_index;
} Client;

User users[MAX_USERS];
int user_count = 0;
Client clients[MAX_CLIENTS];

void current_timestamp(char *out){
    time_t now = time(NULL);
    struct tm *tmv = localtime(&now);
    if(!tmv){
        strcpy(out, "1970-01-01 00:00:00");
        return;
    }
    sprintf(out, "%04d-%02d-%02d %02d:%02d:%02d",
            tmv->tm_year + 1900, tmv->tm_mon + 1, tmv->tm_mday,
            tmv->tm_hour, tmv->tm_min, tmv->tm_sec);
}

void log_event(char *fmt, ...){
    char ts[32];
    va_list args;

    current_timestamp(ts);
    printf("[%s] ", ts);

    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);

    printf("\n");
    fflush(stdout);
}

int write_all(int fd, char *buf, int len){
    int sent = 0;
    while(sent<len){
        int n = send(fd, buf + sent, len - sent, 0);
        if(n<=0) return -1;
        sent += n;
    }
    return 0;
}

int send_line(int fd, char *line){
    char out[MAX_LINE + 4];
    int n = strlen(line);
    if(n>MAX_LINE) return -1;
    memcpy(out, line, n);
    out[n++] = '\r';
    out[n++] = '\n';
    return write_all(fd, out, n);
}

void to_lower_copy(char *dst, char *src){
    int i = 0;
    while(src[i]!='\0' && i<63){
        dst[i] = (char)tolower((unsigned char)src[i]);
        i++;
    }
    dst[i] = '\0';
}

int is_valid_username(char *s){
    int len = strlen(s);
    if(len==0 || len>20) return 0;
    for(int i=0; i<len; i++){
        if(s[i]<'a' || s[i]>'z') return 0;
    }
    return 1;
}

int is_valid_password(char *s){
    int len = strlen(s);
    if(len==0 || len>30) return 0;
    for(int i=0; i<len; i++){
        if (!isalnum((unsigned char)s[i])) return 0;
    }
    return 1;
}

int ensure_mailbox_dir(char *username){
    char path[256];
    if (mkdir("mailboxes", 0777)<0 && errno!=EEXIST) return -1;

    snprintf(path, sizeof(path), "mailboxes/%s", username);
    if (mkdir(path, 0777)<0 && errno!=EEXIST) return -1;
    return 0;
}

int parse_mail_id_from_name(char *name){
    int len = strlen(name);
    int id = 0;

    if(len<5) return -1;
    if(strcmp(name+len-4, ".txt")!=0) return -1;
    for(int i=0; i<len-4; i++){
        if(!isdigit((unsigned char)name[i])) return -1;
        id = id*10 + (name[i]-'0');
    }
    return id > 0 ? id : -1;
}

int compute_next_id(char *username){
    char path[256];
    DIR *dir;
    struct dirent *ent;
    int max_id = 0;

    snprintf(path, sizeof(path), "mailboxes/%s", username);
    dir = opendir(path);
    if(!dir) return 1;

    while((ent=readdir(dir))!=NULL){
        int id = parse_mail_id_from_name(ent->d_name);
        if (id>max_id) max_id = id;
    }
    closedir(dir);
    return max_id+1;
}

int find_user(char *username_input){
    char lowered[64];
    to_lower_copy(lowered, username_input);

    for(int i=0; i<user_count; i++){
        if(strcmp(users[i].username, lowered)==0) return i;
    }
    return -1;
}

unsigned long djb2(char *str){
    unsigned long hash = 5381;
    int c;
    while((c = *str++)) hash = ((hash << 5) + hash) + (unsigned long)c;
    return hash;
}

int load_users(char *userfile){
    FILE *fp;
    char line[256];
    int lineno = 0;

    fp = fopen(userfile, "r");
    if(!fp){
        perror("userfile");
        return -1;
    }

    while(fgets(line, sizeof(line), fp) != NULL){
        char u[64];
        char p[64];
        char extra[8];
        int parts;
        lineno++;

        line[strcspn(line, "\r\n")] = '\0';
        if(line[0]=='\0') continue;

        parts = sscanf(line, "%63s %63s %7s", u, p, extra);
        if(parts!=2){
            fprintf(stderr, "Malformed userfile line %d\n", lineno);
            fclose(fp);
            return -1;
        }

        if(!is_valid_username(u) || !is_valid_password(p)){
            fprintf(stderr, "Invalid username/password at line %d\n", lineno);
            fclose(fp);
            return -1;
        }

        if(user_count>=MAX_USERS){
            fprintf(stderr, "Too many users (max %d)\n", MAX_USERS);
            fclose(fp);
            return -1;
        }

        if(find_user(u)>=0){
            fprintf(stderr, "Duplicate username at line %d\n", lineno);
            fclose(fp);
            return -1;
        }

        strcpy(users[user_count].username, u);
        strcpy(users[user_count].password, p);

        if(ensure_mailbox_dir(users[user_count].username)<0){
            perror("mkdir");
            fclose(fp);
            return -1;
        }
        users[user_count].next_id = compute_next_id(users[user_count].username);

        user_count++;
    }

    fclose(fp);
    return 0;
}

int list_message_ids(char *username, int *ids, int max_ids){
    char path[256];
    DIR *dir;
    struct dirent *ent;
    int count = 0;

    snprintf(path, sizeof(path), "mailboxes/%s", username);
    dir = opendir(path);
    if(!dir) return 0;

    while((ent = readdir(dir))!=NULL){
        int id = parse_mail_id_from_name(ent->d_name);
        if(id>0 && count<max_ids){
            ids[count++] = id;
        }
    }
    closedir(dir);

    for(int i=0; i<count; i++){
        for(int j=i+1; j<count; j++){
            if(ids[j]<ids[i]){
                int t = ids[i];
                ids[i] = ids[j];
                ids[j] = t;
            }
        }
    }

    return count;
}

int extract_headers(char *path, char *from, char *subject, char *date){
    FILE *fp = fopen(path, "r");
    char line[512];
    if(!fp) return -1;

    from[0] = '\0';
    subject[0] = '\0';
    date[0] = '\0';

    while (fgets(line, sizeof(line), fp)!=NULL){
        line[strcspn(line, "\r\n")] = '\0';
        if (strncmp(line, "From: ", 6)==0) sscanf(line + 6, "%255[^\n]", from);
        else if (strncmp(line, "Subject: ", 9)==0) sscanf(line + 9, "%255[^\n]", subject);
        else if (strncmp(line, "Date: ", 6)==0) sscanf(line + 6, "%63[^\n]", date);
        else if (strcmp(line, "---")==0) break;
    }

    fclose(fp);
    return 0;
}

void reset_smtp(Client *c){
    c->smtp_state = SMTP_WAIT_FROM;
    c->sender[0] = '\0';
    strcpy(c->subject, "(no subject)");
    c->recipient_count = 0;
    c->body_len = 0;
    c->body[0] = '\0';
    c->body_too_large = 0;
}

void close_client(Client *c, fd_set *master){
    if(!c->active) return;
    close(c->fd);
    FD_CLR(c->fd, master);
    log_event("Client disconnected");
    memset(c, 0, sizeof(*c));
    c->fd = -1;
}

void start_mode_recv(Client *c){
    char alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    
    c->mode = MODE_RECV;
    c->auth_attempts = 0;
    c->auth_user_index = -1;
    for(int i=0; i<8; i++) c->nonce[i] = alphabet[rand() % (int)(sizeof(alphabet) - 1)];
    c->nonce[8] = '\0';
    send_line(c->fd, "OK");
    char msg[64];
    snprintf(msg, sizeof(msg), "AUTH REQUIRED %s", c->nonce);
    send_line(c->fd, msg);
}

void start_mode_send(Client *c){
    c->mode = MODE_SEND;
    reset_smtp(c);
    send_line(c->fd, "OK");
}

int recipient_exists(Client *c, char *username_lower){
    for(int i=0; i<c->recipient_count; i++){
        if(strcmp(c->recipients[i], username_lower)==0) return 1;
    }
    return 0;
}

void deliver_mail(Client *c){
    char date[32];
    char rcpt_list[512];

    current_timestamp(date);

    rcpt_list[0] = '\0';
    strcat(rcpt_list, "[");
    for(int i=0; i<c->recipient_count; i++){
        strcat(rcpt_list, c->recipients[i]);
        if(i + 1 < c->recipient_count) strcat(rcpt_list, ",");
    }
    strcat(rcpt_list, "]");

    for(int i=0; i<c->recipient_count; i++){
        int uid = find_user(c->recipients[i]);
        if(uid>=0){
            char path[256];
            FILE *fp;

            snprintf(path, sizeof(path), "mailboxes/%s/%d.txt",
                     users[uid].username, users[uid].next_id++);
            fp = fopen(path, "w");
            if(!fp) continue;

            fprintf(fp, "From: %s\n", c->sender);
            fprintf(fp, "To: ");
            for(int j=0; j<c->recipient_count; j++){
                fprintf(fp, "%s", c->recipients[j]);
                if (j + 1 < c->recipient_count) fprintf(fp, ", ");
            }
            fprintf(fp, "\n");
            fprintf(fp, "Subject: %s\n", c->subject);
            fprintf(fp, "Date: %s\n", date);
            fprintf(fp, "---\n");
            fprintf(fp, "%s", c->body);
            fclose(fp);
        }
    }

    char resp[96];
    snprintf(resp, sizeof(resp), "OK Delivered to %d mailboxes", c->recipient_count);
    send_line(c->fd, resp);

    if(c->recipient_count==1)
        log_event("Mail delivered from \"%s\" to %s (1 recipient)", c->sender, rcpt_list);
    else
        log_event("Mail delivered from \"%s\" to %s (%d recipients)", c->sender, rcpt_list, c->recipient_count);
    reset_smtp(c);
}

void handle_smtp_line(Client *c, char *line, fd_set *master){
    if(strcmp(line, "QUIT")==0){
        send_line(c->fd, "BYE");
        close_client(c, master);
        return;
    }
    if(c->smtp_state==SMTP_READING_BODY){
        if(strcmp(line, ".")==0){
            if(c->body_too_large){
                send_line(c->fd, "ERR Body too large");
                reset_smtp(c);
                return;
            }
            deliver_mail(c);
            return;
        }

        char *content = line;
        int line_len;
        if (line[0]=='.') content = line+1;
        line_len = strlen(content);

        if(c->body_len+line_len+1>BODY_LIMIT){
            c->body_too_large = 1;
            return;
        }

        memcpy(c->body + c->body_len, content, line_len);
        c->body_len += line_len;
        c->body[c->body_len++] = '\n';
        c->body[c->body_len] = '\0';
        return;
    }

    if(strncmp(line, "FROM ", 5)==0){
        snprintf(c->sender, sizeof(c->sender), "%s", line + 5);
        c->recipient_count = 0;
        strcpy(c->subject, "(no subject)");
        c->smtp_state = SMTP_WAIT_TO_OR_SUB;
        send_line(c->fd, "OK Sender accepted");
        return;
    }

    if(strncmp(line, "TO ", 3)==0){
        char lowered[32];
        if(c->smtp_state!=SMTP_WAIT_TO_OR_SUB){
            send_line(c->fd, "ERR Bad sequence");
            return;
        }
        to_lower_copy(lowered, line + 3);
        if(find_user(lowered)<0){
            send_line(c->fd, "ERR No such user");
            return;
        }
        if (!recipient_exists(c, lowered) && c->recipient_count < MAX_RECIPIENTS) {
            strcpy(c->recipients[c->recipient_count++], lowered);
        }
        send_line(c->fd, "OK Recipient accepted");
        return;
    }
    if(strncmp(line, "SUB", 3)==0){
        if(c->smtp_state!=SMTP_WAIT_TO_OR_SUB){
            send_line(c->fd, "ERR Bad sequence");
            return;
        }
        if(line[3]=='\0') strcpy(c->subject, "(no subject)");
        else if(line[3]==' '){
            snprintf(c->subject, sizeof(c->subject), "%s", line + 4);
            if (c->subject[0] == '\0') strcpy(c->subject, "(no subject)");
        }
        else{
            send_line(c->fd, "ERR Unknown command");
            return;
        }
        c->smtp_state = SMTP_WAIT_BODY_CMD;
        send_line(c->fd, "OK Subject accepted");
        return;
    }
    if(strcmp(line, "BODY")==0){
        if(c->smtp_state!=SMTP_WAIT_BODY_CMD){
            send_line(c->fd, "ERR Bad sequence");
            return;
        }
        if(c->recipient_count<=0){
            send_line(c->fd, "ERR No valid recipients");
            return;
        }
        c->smtp_state = SMTP_READING_BODY;
        c->body_len = 0;
        c->body[0] = '\0';
        c->body_too_large = 0;
        send_line(c->fd, "OK Send body, end with CRLF.CRLF");
        return;
    }
    if (strncmp(line, "FROM", 4) == 0 || strncmp(line, "TO", 2) == 0 ||
        strncmp(line, "SUB", 3) == 0 || strncmp(line, "BODY", 4) == 0) {
        send_line(c->fd, "ERR Bad sequence");
        return;
    }

    send_line(c->fd, "ERR Unknown command");
}

void handle_smp_authenticated(Client *c, char *line){
    User *u = &users[c->auth_user_index];

    if(strcmp(line, "QUIT")==0){
        send_line(c->fd, "BYE");
        c->mode = MODE_NONE;
        return;
    }
    if(strcmp(line, "COUNT")==0){
        int ids[4096];
        int count = list_message_ids(u->username, ids, 4096);
        char resp[64];
        snprintf(resp, sizeof(resp), "OK %d", count);
        send_line(c->fd, resp);
        // log_event("User %s COUNT", u->username);
        return;
    }
    if(strcmp(line, "LIST")==0){
        int ids[4096];
        int count = list_message_ids(u->username, ids, 4096);
        char resp[64];

        snprintf(resp, sizeof(resp), "OK %d messages", count);
        send_line(c->fd, resp);

        for(int i=0; i<count; i++){
            char path[256];
            char from[256];
            char subject[256];
            char date[64];
            char linebuf[700];

            snprintf(path, sizeof(path), "mailboxes/%s/%d.txt", u->username, ids[i]);
            if(extract_headers(path, from, subject, date)<0) continue;

            snprintf(linebuf, sizeof(linebuf), "%d\t%s\t%s\t%s", ids[i], from, subject, date);
            send_line(c->fd, linebuf);
        }

        send_line(c->fd, ".");
        log_event("User %s LIST", u->username);
        return;
    }
    if(strncmp(line, "READ ", 5)==0){
        int id = atoi(line + 5);
        char path[256];
        FILE *fp;
        char fileline[600];

        snprintf(path, sizeof(path), "mailboxes/%s/%d.txt", u->username, id);
        fp = fopen(path, "r");
        if(!fp){
            send_line(c->fd, "ERR No such message");
            return;
        }

        send_line(c->fd, "OK");
        while(fgets(fileline, sizeof(fileline), fp)!=NULL){
            char out[700];
            fileline[strcspn(fileline, "\r\n")] = '\0';
            if(fileline[0]=='.'){
                snprintf(out, sizeof(out), ".%s", fileline);
                send_line(c->fd, out);
            }
            else send_line(c->fd, fileline);
        }
        fclose(fp);
        send_line(c->fd, ".");
        log_event("User %s READ message %d", u->username, id);
        return;
    }
    if(strncmp(line, "DELETE ", 7)==0){
        int id = atoi(line + 7);
        char path[256];

        snprintf(path, sizeof(path), "mailboxes/%s/%d.txt", u->username, id);
        if(remove(path)==0){
            send_line(c->fd, "OK Deleted");
            log_event("User %s DELETE message %d", u->username, id);
        }
        else send_line(c->fd, "ERR No such message");
        return;
    }

    send_line(c->fd, "ERR Unknown command");
}

void handle_smp_line(Client *c, char *line, fd_set *master){
    if(c->auth_user_index>=0){
        handle_smp_authenticated(c, line);
        if(c->mode==MODE_NONE) close_client(c, master);
        return;
    }

    if(strncmp(line, "AUTH ", 5)==0){
        char username[64];
        unsigned long hash = 0;
        char lowered[64];
        int parsed;

        parsed = sscanf(line + 5, "%63s %lu", username, &hash);
        if(parsed==2){
            int uid;
            char combo[128];

            to_lower_copy(lowered, username);
            uid = find_user(lowered);
            if(uid>=0){
                snprintf(combo, sizeof(combo), "%s%s", users[uid].password, c->nonce);
                if(djb2(combo)==hash){
                    char resp[96];
                    c->auth_user_index = uid;
                    snprintf(resp, sizeof(resp), "OK Welcome %s", users[uid].username);
                    send_line(c->fd, resp);
                    log_event("Authentication successful for user %s", users[uid].username);
                    return;
                }
            }
        }
        c->auth_attempts++;
        send_line(c->fd, "ERR Authentication failed");
        log_event("Authentication failed");
        if(c->auth_attempts>=3){
            send_line(c->fd, "ERR Too many failures");
            close_client(c, master);
        }
        return;
    }

    send_line(c->fd, "ERR Unknown command");
}

void handle_client_line(Client *c, char *line, fd_set *master){
    if(c->mode==MODE_NONE){
        if(strcmp(line, "MODE SEND")==0){
            start_mode_send(c);
            log_event("Client selected MODE SEND");
            return;
        }
        if(strcmp(line, "MODE RECV")==0){
            start_mode_recv(c);
            log_event("Client selected MODE RECV");
            return;
        }
        if(strcmp(line, "QUIT")==0){
            send_line(c->fd, "BYE");
            close_client(c, master);
            return;
        }
        send_line(c->fd, "ERR Unknown mode");
        return;
    }

    if(c->mode==MODE_SEND) handle_smtp_line(c, line, master);
    else if(c->mode==MODE_RECV) handle_smp_line(c, line, master);
}

void process_socket_data(Client *c, fd_set *master){
    char buf[1024];
    ssize_t n = recv(c->fd, buf, sizeof(buf), 0);

    if(n<=0){
        close_client(c, master);
        return;
    }

    for(int i=0; i<n; i++){
        char ch = buf[i];
        int max_allowed = (c->mode == MODE_SEND) ? 510 : MAX_LINE;

        if(ch=='\r') continue;
        if(ch=='\n'){
            if(c->line_too_long){
                send_line(c->fd, "ERR Line too long");
                c->line_too_long = 0;
            }
            else{
                c->inbuf[c->inbuf_len] = '\0';
                handle_client_line(c, c->inbuf, master);
            }
            c->inbuf_len = 0;
            if(!c->active) return;
            continue;
        }

        if(c->inbuf_len<max_allowed) c->inbuf[c->inbuf_len++] = ch;
        else c->line_too_long = 1;
    }
}

Client *alloc_client_slot(void){
    for(int i=0; i<MAX_CLIENTS; i++){
        if(!clients[i].active){
            clients[i].active = 1;
            clients[i].fd = -1;
            reset_smtp(&clients[i]);
            return &clients[i];
        }
    }
    return NULL;
}

int main(int argc, char *argv[]){
    int listen_fd;
    struct sockaddr_in serv;
    fd_set master;
    int fdmax;

    if(argc!=3){
        fprintf(stderr, "Usage: %s <port> <userfile>\n", argv[0]);
        return 1;
    }

    srand((unsigned int)(time(NULL)^getpid()));

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(listen_fd<0){
        perror("socket");
        return 1;
    }

    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = INADDR_ANY;
    serv.sin_port = htons((unsigned short)atoi(argv[1]));

    if(bind(listen_fd, (struct sockaddr *)&serv, sizeof(serv))< 0){
        perror("bind");
        close(listen_fd);
        return 1;
    }
    if(listen(listen_fd, BACKLOG)<0){
        perror("listen");
        close(listen_fd);
        return 1;
    }
    log_event("Server started on port %s", argv[1]);
    
    if(load_users(argv[2])<0) return 1;
    log_event("Loaded %d users from %s", user_count, argv[2]);

    memset(clients, 0, sizeof(clients));
    for(int i=0; i<MAX_CLIENTS; i++) clients[i].fd = -1;

    FD_ZERO(&master);
    FD_SET(listen_fd, &master);
    fdmax = listen_fd;

    while(1){
        fd_set readfds = master;
        struct timeval tv;

        tv.tv_sec = 1;
        tv.tv_usec = 0;

        if(select(fdmax + 1, &readfds, NULL, NULL, &tv)<0){
            if(errno==EINTR) continue;
            perror("select");
            break;
        }

        if(FD_ISSET(listen_fd, &readfds)){
            struct sockaddr_in cli;
            socklen_t clen = sizeof(cli);
            int cfd = accept(listen_fd, (struct sockaddr *)&cli, &clen);
            if(cfd>=0){
                Client *slot = alloc_client_slot();
                if(!slot) close(cfd);
                else{
                    slot->fd = cfd;
                    slot->addr = cli;
                    slot->connected_at = time(NULL);
                    slot->mode = MODE_NONE;
                    slot->inbuf_len = 0;
                    slot->line_too_long = 0;
                    slot->auth_attempts = 0;
                    slot->auth_user_index = -1;
                    FD_SET(cfd, &master);
                    if (cfd > fdmax) fdmax = cfd;
                    send_line(cfd, "WELCOME SimpleMail v1.0");
                    log_event("New connection from %s:%d", inet_ntoa(cli.sin_addr), ntohs(cli.sin_port));
                }
            }
        }

        for(int i=0; i<MAX_CLIENTS; i++){
            if(!clients[i].active) continue;

            if(FD_ISSET(clients[i].fd, &readfds)) process_socket_data(&clients[i], &master);
        }

        for(int i=0; i<MAX_CLIENTS; i++){
            if(!clients[i].active) continue;
            if(clients[i].mode==MODE_NONE &&
                time(NULL) - clients[i].connected_at>=MODE_TIMEOUT_SECONDS){
                close_client(&clients[i], &master);
            }
        }

        while(fdmax>=0 && !FD_ISSET(fdmax, &master)) fdmax--;
    }

    close(listen_fd);
    return 0;
}
