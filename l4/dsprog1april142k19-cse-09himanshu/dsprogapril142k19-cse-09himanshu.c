/**************************
Name: Himanshu Tiwari
Roll Number: 2k19/CSE/09
Date of Assignment: 13-April-2020
Assignment Name: Implementation of Bully algorithm over UDP sockets
**************************/


#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#define TRUE 1
#define FALSE 0
#define ML 1024
#define MPROC 32

int ports[MPROC] = {0};
int adj[MPROC][MPROC] = {0};
int numProc = 0;

FILE *fp;

int scanInt(int *number) { 
    int c, n=0;
    c = fgetc(fp);   
    while(c < 48 || c > 57) {
    	c = fgetc(fp);
    } 
    for (; (c>47 && c<58); c=fgetc(fp)) 
        n = n * 10 + c - 48;
    *number = n;  
    return (c == '\n' || c == EOF); 
} 

int scanInput() {
	int id = 0;
	while(scanInt(&id) == 0) {
		numProc++;
		int port, v, lineEnd;
		scanInt(&port);
		ports[id] = port;
		int itr = 0;
		while(1) {
			lineEnd = scanInt(&v);
			adj[id][itr++] = v;
			if(lineEnd) break;
		}
	}
	return id;
}

// Creates and binds the socket. Returns the socket id
int connect_to_port(int connect_to) {
	int sock_id;
	int opt = 1;
	struct sockaddr_in server;
	if ((sock_id = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		printf("unable to create a socket");
		exit(EXIT_FAILURE);
	}
	setsockopt(sock_id, SOL_SOCKET, SO_REUSEADDR, (const void *)&opt, sizeof(int));
	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons(connect_to);
	if (bind(sock_id, (const struct sockaddr *)&server, sizeof(server)) < 0) {
		printf("unable to bind to port");
		exit(EXIT_FAILURE);
	}
	return sock_id;	
}

// send message to port
void send_to_id(unsigned int to, unsigned int id, char message[ML]) {
	struct sockaddr_in cl;
	memset(&cl, 0, sizeof(cl));

	cl.sin_family = AF_INET;
	cl.sin_addr.s_addr = INADDR_ANY;
	cl.sin_port = htons(to);
	sendto(id, (const char *)message, strlen(message), MSG_CONFIRM, (const struct sockaddr *)&cl,	   sizeof(cl));
}

// It initiates the election
int election(int id, int *procs, int num_procs, int self, int initiator) {
	int itr;
	char message[ML];
	if(initiator)
		strcpy(message, "ELECTION");
	else 
		strcpy(message, "FORWARD");
	int is_new_coord = 1;
	for (itr = 0; itr < num_procs; itr += 1) {
		if (procs[itr] > self) {
			printf("sending %s to: %d\n",message, procs[itr]);
			send_to_id(procs[itr], id, message);
			is_new_coord = 0; // a proc with id > self exists thus cannot be coord
		}
	}
	return is_new_coord;
}

// sends hello message to all neighbours
void send_hello(int id, int *procs, int num_procs, int self) {
	int itr;
	char message[ML];
	strcpy(message, "HELLO");
	for (itr = 0; itr < num_procs; itr += 1) {
		if(procs[itr] != self) {
			int ID = id;
			printf("sending HELLO to: %d\n", procs[itr]);
			send_to_id(procs[itr], ID, message);
		}
	}
}

// The new coordinator announces the completion to its neighbours
void announce_completion(int id, int *procs, int num_procs, int self) {
	int itr;
	char message[ML];
	strcpy(message, "COORDINATOR");
	char selfid[10];
	sprintf(selfid, "%d", self);
	strcpy(message, "COORDINATOR=");
	strcpy(message+12, selfid);
	for (itr = 0; itr < num_procs; itr += 1) {
		int ID = id;
		if (procs[itr] < self)
			send_to_id(procs[itr], ID, message);
	}
}

// Announces the new coordinator, used by the process who initiates the election
void announce_new_coordinator(int id, int *procs, int num_procs, int self) {
	int itr;
	char message[ML];
	strcpy(message, "COORDINATOR=");
	strcpy(message+12, "1029");
	for (itr = 0; itr < num_procs; itr += 1) {
		int ID = id;
		if (procs[itr] != self)
			send_to_id(procs[itr], ID, message);
	}
}

int main(int argc, char* argv[]) {
	time_t t;
    time(&t);
    printf("\nDate and Time: %s", ctime(&t));

	fp = fopen("input.txt", "r");
	int election_node = scanInput();
	fclose(fp);	
	int selfId = atoi(argv[1]);
    int self = ports[selfId];
	int n_proc = numProc;
	int procs[MPROC] = {0};
	int sock_id, bully_id;
	int itr, n, start_at;
	unsigned int len;
	char buff[ML], message[ML];
	struct sockaddr_in from;

	for (itr = 0; itr < numProc; itr += 1){
		if(adj[selfId][itr] == 0) {
			n_proc = itr;
			break;
		}
		procs[itr] = ports[adj[selfId][itr]];
	}
	
	start_at = (selfId == election_node);


	printf("creating a process on port %d with id %d \n", self, selfId);
	sock_id = connect_to_port(self);

	if (start_at == TRUE) {
		char choice[5];
		printf("Do you want to send the HELLO message? y/n\n");
		scanf("%s", choice);
		if (choice[0] == 'y' || choice[0] == 'Y') {
			send_hello(sock_id, procs, n_proc, self);
		}
		
		printf("Do you want to send the ELECTION message?\n");
		scanf("%s", choice);
		if ((choice[0] == 'y' || choice[0] == 'Y') && election(sock_id, procs, n_proc, self, 1)) {
			announce_completion(sock_id, procs, n_proc, self);
			printf("ANNOUNCING SELF AS NEW COORDINATOR\n");
			close(sock_id);
		}
		announce_new_coordinator(sock_id, procs, n_proc, self);
		memset(message, 0, sizeof(from));
		memset(buff, 0, sizeof(from));
		memset(&from, 0, sizeof(from));
		n = recvfrom(sock_id, (char *)buff, ML, MSG_WAITALL, (struct sockaddr *)&from, &len);

		buff[n] = '\0';
		if (strcmp(buff, "COORDINATOR") == '=') {
			printf("recieved %s\n",buff);
			announce_new_coordinator(sock_id, procs, n_proc, self);
			close(sock_id);
		}
	}

	while(TRUE && start_at == 0) {
		memset(message, 0, sizeof(from));
		memset(buff, 0, sizeof(from));
		memset(&from, 0, sizeof(from));
		n = recvfrom(sock_id, (char *)buff, ML, MSG_WAITALL, (struct sockaddr *)&from, &len);

		buff[n] = '\0';
		if(strcmp(buff, "HELLO") == 0) {
			printf("recieved %s from %d\n", buff, election_node);
		}
		else if (strcmp(buff, "ELECTION") == 0 || strcmp(buff, "FORWARD") == 0) {			
			if (election(sock_id, procs, n_proc, self, 0)) {
				announce_completion(sock_id, procs, n_proc, self);
				printf("ANNOUNCING SELF AS NEW COORDINATOR\n");
				close(sock_id);
				break;
			}
		}
		else if (strcmp(buff, "COORDINATOR") == 0) {
			bully_id = from.sin_port;
			printf("%d selected as COORDINATOR\n",ntohs(bully_id));
			announce_new_coordinator(sock_id, procs, n_proc, self);
			close(sock_id);
			break;
		}
		else if (strcmp(buff, "COORDINATOR") == '=') {
			printf("recieved %s\n",buff);
			announce_new_coordinator(sock_id, procs, n_proc, self);
			close(sock_id);
			break;
		}
	}
}


