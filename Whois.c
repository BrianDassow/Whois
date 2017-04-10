#include<netdb.h> 
#include<unistd.h>
#include<sys/socket.h>
#include<stdio.h>
#include<string.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include<stdlib.h>
 
int main() {
    char *ip[500];
    char *hostIP = NULL;
	char *dataRecieved = NULL;
	char *ipString = NULL;
	char *searchString = NULL;
	
	//Scan for ip to search
    printf("Whois: ");
    scanf("%s" , ip);
     
	//do first search
	whois(ip, &hostIP, "whois.iana.org");
	searchString = strtok(hostIP , "\n");

	//search the string for whois.
    while(searchString != NULL)
    {
        ipString = strstr(searchString , "whois.");
        if(ipString != NULL)
        {
            break;
        }
        searchString = strtok(NULL , "\n");
    }
	
	//do second search
	whois(ip, &dataRecieved, ipString);
	
	//display data
	printf("\n%s\n\nDone", dataRecieved);
	
    return 0;
}

void whois(char *ip, char **data, char *host) {
    int sock;
	int read_size = 0;
	int total_size = 0;
	char message[100]; 
	char buffer[5000];
	char *response = NULL;
	char whoisIP;
	char *configureInet = NULL;
	struct hostent *he;
    struct in_addr **addr_list;
    int i;
	struct sockaddr_in socketaddr;
    struct sockaddr_in *socketaddrp = &socketaddr;
       
	//get hostname
    if ((he = gethostbyname(host)) == NULL) {
        herror("gethostbyname");
    }
 
	//setup structure
    addr_list = (struct in_addr **) he->h_addr_list;
    for(i = 0; addr_list[i] != NULL; i++) 
    {
		configureInet = inet_ntoa(*addr_list[i]);
    }
	
    if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        printf("Can't create TCP socket.\n");
        exit(-1);
    }

    socketaddr.sin_family = AF_INET;
    socketaddr.sin_port = htons(43);
	inet_pton(AF_INET, configureInet, (void *)(&socketaddr.sin_addr));

	//connect to host
    if (connect(sock, (struct sockaddr *) socketaddrp, sizeof(struct sockaddr_in)) < 0) {
        printf("could not connect to host.\n");
        exit(-1);
    }
	
	//query host
	sprintf(message, "%s\r\n", ip);
	if(send(sock, message, strlen(message) , 0) < 0) {
        perror("send failed");
    }
	
	//get response from host
	while((read_size = recv(sock, buffer, sizeof(buffer), 0))) {
        response = realloc(response , read_size + total_size);
        if(response == NULL)
        {
            printf("realloc failed");
        }
        memcpy(response + total_size , buffer , read_size);
        total_size += read_size;
    }

    response = realloc(response , total_size + 1);
	*data = response;
}