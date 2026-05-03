#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define BUF_SIZE 2048
#define BODY_LINE_MAX 1024

unsigned long djb2(char *str){
    unsigned long hash = 5381;
    int c;
    while((c = *str++)) hash = ((hash << 5) + hash) + (unsigned long)c;
    return hash;
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
    char out[BUF_SIZE + 4];
    int n = strlen(line);
    if(n>BUF_SIZE) return -1;
    memcpy(out, line, n);
    out[n++] = '\r';
    out[n++] = '\n';
    return write_all(fd, out, n);
}

int read_line(int fd, char *out){
    int i = 0;
    char ch;

    while(1){
        ssize_t n = recv(fd, &ch, 1, 0);
        if(n<=0) return -1;
        if(ch=='\r') continue;
        if(ch=='\n'){
            if(i>=BUF_SIZE) return -1;
            out[i] = '\0';
            return 0;
        }
        if(i+1<BUF_SIZE) out[i++] = ch;
        else return -1;
    }
}

int connect_server(char *ip, int port){
    int sockfd;
    struct sockaddr_in serv;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd<0){
        perror("socket");
        return -1;
    }

    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_port = htons((unsigned short)port);
    if(inet_pton(AF_INET, ip, &serv.sin_addr)!=1){
        fprintf(stderr, "Invalid server IP\n");
        close(sockfd);
        return -1;
    }

    if(connect(sockfd, (struct sockaddr *)&serv, sizeof(serv))<0){
        perror("connect");
        close(sockfd);
        return -1;
    }

    return sockfd;
}

int connect_and_greet(char *ip, int port){
    int sockfd = connect_server(ip, port);
    char line[BUF_SIZE];
    if(sockfd<0) return -1;
    if(read_line(sockfd, line)<0){
        close(sockfd);
        return -1;
    }
    if(strcmp(line, "WELCOME SimpleMail v1.0")!=0){
        fprintf(stderr, "Unexpected server greeting: %s\n", line);
        close(sockfd);
        return -1;
    }
    return sockfd;
}

void trim_newline(char *s){
    s[strcspn(s, "\r\n")] = '\0';
}

int prompt_int(char *msg){
    char line[64];
    char *end;
    long val;

    while(1){
        printf("%s", msg);
        if(!fgets(line, sizeof(line), stdin)) return -1;
        trim_newline(line);
        if(line[0]=='\0') continue;
        val = strtol(line, &end, 10);
        if(*end=='\0') return val;
        printf("Please enter a valid number.\n");
    }
}

int starts_with(char *s, char *prefix){
    int n = strlen(prefix);
    return strncmp(s, prefix, n)==0;
}

void send_mail_flow(char *ip, int port){
    int sockfd = connect_and_greet(ip, port);
    char line[BUF_SIZE];
    char from[256];
    char subject[256];
    int accepted_count = 0;

    if(sockfd<0){
        printf("Could not connect to server.\n");
        return;
    }
    if(send_line(sockfd, "MODE SEND")<0 || read_line(sockfd, line)<0){
        printf("Connection error during MODE SEND.\n");
        close(sockfd);
        return;
    }
    if(strcmp(line, "OK")!=0){
        printf("Server error: %s\n", line);
        close(sockfd);
        return;
    }

    printf("\nFrom (your name): ");
    if(!fgets(from, sizeof(from), stdin)){
        close(sockfd);
        return;
    }
    trim_newline(from);

    char cmd[BUF_SIZE];
    snprintf(cmd, sizeof(cmd), "FROM %s", from);
    send_line(sockfd, cmd);
    if(read_line(sockfd, line)<0 || !starts_with(line, "OK")){
        printf("Server error: %s\n", line);
        close(sockfd);
        return;
    }

    while(1){
        char to[64];
        char lowered[64];
        int i;

        printf("To (recipient username, empty line to finish): ");
        if (!fgets(to, sizeof(to), stdin)) {
            close(sockfd);
            return;
        }
        trim_newline(to);
        if(to[0]=='\0'){
            if(accepted_count>0) break;
            printf("At least one valid recipient is required.\n");
            continue;
        }
        for(i=0; to[i]!='\0' && i<63; i++) lowered[i] = (char)tolower((unsigned char)to[i]);
        lowered[i] = '\0';

        snprintf(cmd, sizeof(cmd), "TO %s", lowered);
        send_line(sockfd, cmd);
        if(read_line(sockfd, line)<0) {
            printf("Connection lost while sending recipient.\n");
            close(sockfd);
            return;
        }
        if(starts_with(line, "OK")){
            accepted_count++;
            printf("  -> Recipient '%s' accepted.\n", lowered);
        }
        else printf("  -> Error: user '%s' does not exist on this server.\n", lowered);
    }

    printf("\nSubject: ");
    if(!fgets(subject, sizeof(subject), stdin)){
        close(sockfd);
        return;
    }
    trim_newline(subject);

    snprintf(cmd, sizeof(cmd), "SUB %s", subject);
    send_line(sockfd, cmd);
    if(read_line(sockfd, line)<0 || !starts_with(line, "OK")){
        printf("Server error: %s\n", line);
        close(sockfd);
        return;
    }

    send_line(sockfd, "BODY");
    if(read_line(sockfd, line)<0){
        printf("Connection lost while entering body.\n");
        close(sockfd);
        return;
    }
    if(!starts_with(line, "OK")){
        printf("Server error: %s\n", line);
        close(sockfd);
        return;
    }

    printf("Body (type '.' on a line by itself to finish):\n");
    while(1){
        char bodyline[BODY_LINE_MAX];
        char cmd[BODY_LINE_MAX + 2];

        if(!fgets(bodyline, sizeof(bodyline), stdin)){
            close(sockfd);
            return;
        }
        trim_newline(bodyline);

        if(strcmp(bodyline, ".")==0){
            send_line(sockfd, ".");
            break;
        }

        if(bodyline[0]=='.') snprintf(cmd, sizeof(cmd), ".%s", bodyline);
        else snprintf(cmd, sizeof(cmd), "%s", bodyline);
        send_line(sockfd, cmd);
    }
    printf("\n");

    if(read_line(sockfd, line)<0){
        printf("Connection lost before delivery confirmation.\n");
        close(sockfd);
        return;
    }

    if(starts_with(line, "OK Delivered to ")){
        int n = 0;
        sscanf(line, "OK Delivered to %d mailboxes", &n);
        printf("Mail delivered to %d recipient%s.\n", n, (n == 1) ? "" : "s");
    }
    else printf("Server error: %s\n", line);
    printf("\n");
    send_line(sockfd, "QUIT");
    read_line(sockfd, line);
    close(sockfd);
}

void list_messages(int sockfd){
    char line[BUF_SIZE];

    send_line(sockfd, "LIST");
    if(read_line(sockfd, line)<0){
        printf("Connection lost during LIST.\n");
        return;
    }

    if(!starts_with(line, "OK ")){
        printf("Server error: %s\n", line);
        return;
    }

    printf("\nID\tFrom\tSubject\tDate\n");
    printf("--\t----\t-------\t----\n");
    while(1){
        if(read_line(sockfd, line)<0){
            printf("Connection lost during LIST response.\n");
            return;
        }
        if(strcmp(line, ".")==0) break;
        printf("%s\n", line);
    }
}

void read_message(int sockfd){
    char line[BUF_SIZE];
    int id = prompt_int("\nEnter message ID: ");

    if(id<=0){
        printf("Invalid message ID.\n");
        return;
    }

    char cmd[64];
    snprintf(cmd, sizeof(cmd), "READ %d", id);
    send_line(sockfd, cmd);

    if(read_line(sockfd, line)<0){
        printf("Connection lost during READ.\n");
        return;
    }

    if(strcmp(line, "OK")!=0){
        printf("%s\n", line);
        return;
    }

    printf("\n");
    while(1){
        if(read_line(sockfd, line)<0){
            printf("Connection lost during message read.\n");
            return;
        }
        if(strcmp(line, ".")==0) break;
        if(line[0]=='.' && line[1]=='.') printf("%s\n", line + 1);
        else printf("%s\n", line);
    }
}

void delete_message(int sockfd){
    char line[BUF_SIZE];
    int id = prompt_int("\nEnter message ID: ");

    if(id<=0){
        printf("Invalid message ID.\n");
        return;
    }

    char cmd[64];
    snprintf(cmd, sizeof(cmd), "DELETE %d", id);
    send_line(sockfd, cmd);

    if(read_line(sockfd, line)<0) {
        printf("Connection lost during DELETE.\n");
        return;
    }
    if(strcmp(line, "OK Deleted")==0) printf("Message %d deleted.\n", id);
    else printf("%s\n", line);
    printf("\n");
}

int fetch_count(int sockfd){
    char line[BUF_SIZE];
    int count = 0;

    send_line(sockfd, "COUNT");
    if(read_line(sockfd, line)<0) return -1;
    if(sscanf(line, "OK %d", &count)==1) return count;
    return -1;
}

void check_mail_flow(char *ip, int port){
    int sockfd = connect_and_greet(ip, port);
    char line[BUF_SIZE];
    char nonce[64];
    char username[64] = {0};
    int authenticated = 0;
    int attempts = 0;

    if(sockfd<0){
        printf("Could not connect to server.\n");
        return;
    }

    send_line(sockfd, "MODE RECV");
    if(read_line(sockfd, line)<0 || strcmp(line, "OK")!=0){
        printf("Server error: %s\n", line);
        close(sockfd);
        return;
    }

    if(read_line(sockfd, line)<0){
        printf("Connection lost during AUTH setup.\n");
        close(sockfd);
        return;
    }

    if(sscanf(line, "AUTH REQUIRED %63s", nonce)!=1){
        printf("Server error: %s\n", line);
        close(sockfd);
        return;
    }

    while(attempts<3){
        char password[128];
        char combo[256];
        unsigned long hash;
        char cmd[BUF_SIZE];

        printf("Username: ");
        if(!fgets(username, sizeof(username), stdin)){
            close(sockfd);
            return;
        }
        trim_newline(username);

        printf("Password: ");
        if(!fgets(password, sizeof(password), stdin)){
            close(sockfd);
            return;
        }
        trim_newline(password);

        snprintf(combo, sizeof(combo), "%s%s", password, nonce);
        hash = djb2(combo);

        snprintf(cmd, sizeof(cmd), "AUTH %s %lu", username, hash);
        send_line(sockfd, cmd);

        if(read_line(sockfd, line)<0){
            printf("Connection lost during AUTH.\n");
            close(sockfd);
            return;
        }
        if(starts_with(line, "OK Welcome ")){
            printf("Welcome, %s!\n", username);
            authenticated = 1;
            break;
        }
        if(strcmp(line, "ERR Authentication failed")==0){
            printf("Authentication failed.\n");
            attempts++;
            continue;
        }
        if(strcmp(line, "ERR Too many failures")==0){
            printf("Too many failed attempts.\n");
            close(sockfd);
            return;
        }

        printf("Server error: %s\n", line);
        attempts++;
    }

    if(!authenticated){
        printf("Failed to authenticate after 3 attempts.\n");
        close(sockfd);
        return;
    }

    while(1){
        int count = fetch_count(sockfd);
        int op;

        if(count>=0) printf("\nMailbox for %s (%d message%s)\n", username, count, (count == 1) ? "" : "s");
        else printf("\nMailbox for %s\n", username);
        printf("1. List all messages\n");
        printf("2. Read a message\n");
        printf("3. Delete a message\n");
        printf("4. Logout\n");

        op = prompt_int("> ");
        if(op==1) list_messages(sockfd);
        else if(op==2) read_message(sockfd);
        else if(op==3) delete_message(sockfd);
        else if(op==4){
            send_line(sockfd, "QUIT");
            if(read_line(sockfd, line)==0 && strcmp(line, "BYE")==0){
                printf("\nLogged out.\n\n");
            }
            break;
        }
        else printf("Invalid option.\n");
    }

    close(sockfd);
}

int main(int argc, char *argv[]){
    char *ip;
    int port;

    if(argc!=3){
        fprintf(stderr, "Usage: %s <server_ip> <port>\n", argv[0]);
        return 1;
    }

    ip = argv[1];
    port = atoi(argv[2]);

    printf("Connected to SimpleMail server.\n");
    while(1){
        int choice;
        printf("1. Send a mail\n");
        printf("2. Check my mailbox\n");
        printf("3. Quit\n");

        choice = prompt_int("> ");
        if(choice==1) send_mail_flow(ip, port);
        else if(choice==2) check_mail_flow(ip, port);
        else if(choice==3){
            printf("Goodbye.\n");
            break;
        }
        else printf("Invalid option.\n");
    }

    return 0;
}
