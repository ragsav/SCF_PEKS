#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <pbc/pbc.h>
#include <openssl/ssl.h>
#include <openssl/sha.h>
#include <arpa/inet.h>


#define SERVER_PORT 8080
#define SENDER_PORT 8040
#define RECIEVER_PORT 8000



element_t g,g1,u,v,d,h,sks,skr,pks,pkr,c1,c3,s;
char c2[]="";
pairing_t e;

int server_fd, new_socket, valread,sender_fd,reciever_fd;
struct sockaddr_in server_address,sender_address,reciever_address;
int opt = 1;
int server_addrlen = sizeof(server_address),sender_addrlen = sizeof(sender_address),reciever_addrlen = sizeof(reciever_address);
char id_buffer[1024] = {0},secret_buffer[1024] = {0};

char *prev_sender = "nan",*prev_token = "nan";
int serverConnected = -1,senderConnected = -1,recieverConnected = -1;

int sender_socket = 0,server_socket = 0,reciever_socket=0, valread;
char *msg = "sender|connect|nan";
char buffer[4096*8*10] = {0};


void getGlobalSetup()
{

	char param[1024];
	size_t count = fread(param, 1, 1024, stdin);
	if (!count)
	{
		pbc_die("input error");
	}
	OpenSSL_add_all_algorithms();
	pbc_random_set_file("/dev/urandom");
	printf("Global setup running...\n");
	
	printf("Getting global setup and pks...\n");

	pairing_init_set_buf(e, param, count);
	element_init_G1(g,e);
	element_init_G1(g1,e);
	element_init_G1(u,e);
	element_init_G1(v,e);
	element_init_G1(d,e);
	element_init_G1(h,e);

	element_init_G1(c1, e);
	element_init_G1(c3,e);
	element_init_Zr(s,e);

	element_init_G1(pks,e);
	element_init_Zr(sks,e);
	
	


	


	

	FILE *fp_g,*fp_g1,*fp_u,*fp_v,*fp_d,*fp_h,*fp_pks ;

	
	fp_g = fopen("global_setup/g.txt", "rb") ;
	fp_g1 = fopen("global_setup/g1.txt", "rb") ;
	fp_u = fopen("global_setup/u.txt", "rb") ;
	fp_v = fopen("global_setup/v.txt", "rb") ;
	fp_d = fopen("global_setup/d.txt", "rb") ;
	fp_h = fopen("global_setup/h.txt", "rb") ;
	fp_pks = fopen("global_setup/pks.txt", "rb") ;


	if(fp_g&&fp_g1&&fp_u&&fp_v&&fp_d&&fp_h&&fp_pks){

		fseek(fp_g, 0, SEEK_END); 
		long g_len = ftell(fp_g);
		rewind(fp_g);

		fseek(fp_g1, 0, SEEK_END); 
		long g1_len = ftell(fp_g1);
		rewind(fp_g1);

		fseek(fp_u, 0, SEEK_END); 
		long u_len = ftell(fp_u);
		rewind(fp_u);

		fseek(fp_v, 0, SEEK_END); 
		long v_len = ftell(fp_v);
		rewind(fp_v);

		fseek(fp_d, 0, SEEK_END); 
		long d_len = ftell(fp_d);
		rewind(fp_d);

		fseek(fp_h, 0, SEEK_END); 
		long h_len = ftell(fp_h);
		rewind(fp_h);

		fseek(fp_pks, 0, SEEK_END); 
		long pks_len = ftell(fp_pks);
		rewind(fp_pks);




		char *g_bytes = malloc(g_len * sizeof( char));
		char *g1_bytes = malloc(g1_len * sizeof( char));
		char *u_bytes = malloc(u_len * sizeof( char));
		char *v_bytes = malloc(v_len * sizeof( char));
		char *d_bytes = malloc(d_len * sizeof( char));
		char *h_bytes = malloc(h_len * sizeof( char));
		char *pks_bytes = malloc(pks_len * sizeof( char));

		fread(g_bytes, g_len, 1, fp_g);
		fclose(fp_g);
		element_from_bytes_compressed(g, g_bytes);
		free(g_bytes);
		element_printf("g : %B\n\n", g);

		fread(g1_bytes, g1_len, 1, fp_g1);
		fclose(fp_g1);
		element_from_bytes_compressed(g1, g1_bytes);
		free(g1_bytes);
		element_printf("g1 : %B\n\n", g1);

		fread(u_bytes, u_len, 1, fp_u);
		fclose(fp_u);
		element_from_bytes_compressed(u, u_bytes);
		free(u_bytes);
		element_printf("u : %B\n\n", u);

		fread(v_bytes, v_len, 1, fp_v);
		fclose(fp_v);
		element_from_bytes_compressed(v, v_bytes);
		free(v_bytes);
		element_printf("v : %B\n\n", v);
		
		
		fread(d_bytes, d_len, 1, fp_d);
		fclose(fp_d);
		element_from_bytes_compressed(d, d_bytes);
		free(d_bytes);
		element_printf("d : %B\n\n", d);
		
		fread(h_bytes, h_len, 1, fp_h);
		fclose(fp_h);
		element_from_bytes_compressed(h, h_bytes);
		free(h_bytes);
		element_printf("h : %B\n\n", h);

		fread(pks_bytes, pks_len, 1, fp_pks);
		fclose(fp_pks);
		element_from_bytes_compressed(pks, pks_bytes);
		free(pks_bytes);
		element_printf("pks : %B\n\n", pks);

	}
	
}

void KeyGenR()
{
	
	
	element_init_G1(pkr,e);
	element_init_Zr(skr,e);
	element_random(skr);
	element_pow_zn(pkr, g, skr);
	element_printf("Skr = %B\n",skr);
	element_printf("Pkr = %B\n",pkr);


	FILE *fp_pkr ;
	
	fp_pkr = fopen("global_setup/pkr.txt", "w") ;


	if(fp_pkr){
		
		int pkr_len = element_length_in_bytes_compressed(pks);
		char *pkr_bytes = malloc(pkr_len * sizeof( char));
		element_to_bytes_compressed(pkr_bytes, pkr);
		fputs(pkr_bytes, fp_pkr) ;   
	    fputs("\n", fp_pkr) ;
	    fclose(fp_pkr) ;
	    free(pkr_bytes);
	    printf("PKS written\n");
	}


}


int makeSocket(){
	printf("SOCKET INITIALIZATION\n");
	if ((reciever_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
	{
		perror("socket failed");
		exit(EXIT_FAILURE);
	}
	
	if (setsockopt(reciever_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
												&opt, sizeof(opt)))
	{
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}
	reciever_address.sin_family = AF_INET;
	reciever_address.sin_addr.s_addr = INADDR_ANY;
	reciever_address.sin_port = htons( RECIEVER_PORT );
	
	if (bind(reciever_fd, (struct sockaddr *)&reciever_address,
								sizeof(reciever_address))<0)
	{
		perror("bind failed");
		exit(EXIT_FAILURE);
	}
	if (listen(reciever_fd, 3) < 0)
	{
		perror("listen");
		exit(EXIT_FAILURE);
	}
	return 1;
}

int connectToServer(){

	if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		printf("\n Server Socket creation error \n");
		return -1;
	}

	server_address.sin_family = AF_INET;
	server_address.sin_port = htons(SERVER_PORT);
	
	// Convert IPv4 and IPv6 addresses from text to binary form
	if(inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr)<=0)
	{
		printf("\nInvalid address/ Address not supported \n");
		return -1;
	}

	if (connect(server_socket, (struct sockaddr *)&server_address, sizeof(server_address)) < 0)
	{
		printf("\nConnection to server failed \n");
		

		return -1;
	}
	return 1;
}

int connectToSender(){

	if ((sender_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		printf("\n Sender Socket creation error \n");
		return -1;
	}

	sender_address.sin_family = AF_INET;
	sender_address.sin_port = htons(SENDER_PORT);
	
	// Convert IPv4 and IPv6 addresses from text to binary form
	if(inet_pton(AF_INET, "127.0.0.1", &sender_address.sin_addr)<=0)
	{
		printf("\nInvalid address/ Address not supported \n");
		return -1;
	}

	if (connect(sender_socket, (struct sockaddr *)&sender_address, sizeof(sender_address)) < 0)
	{
		printf("\nConnection to sender failed \n");
		
		return -1;
	}
	return 1;
}


int retryToServer(){
	if (connect(server_socket, (struct sockaddr *)&server_address, sizeof(server_address)) < 0)
	{
		printf("\nConnection to server failed \n");
		return -1;
	}
	return 1;
}

int retryToSender(){
	if (connect(sender_socket, (struct sockaddr *)&sender_address, sizeof(sender_address)) < 0)
	{
		printf("\nConnection to sender failed \n");
		return -1;
	}
	return 1;
}

void getPEKS(){
	FILE *fp_c1,*fp_c2,*fp_c3 ;
	//fp_s= fopen("global_setup/s.txt", "rb") ;
	fp_c1 = fopen("global_setup/c1.txt", "rb") ;
	fp_c2= fopen("global_setup/c2.txt", "rb") ;
	fp_c3 = fopen("global_setup/c3.txt", "rb") ;
	


	if(fp_c1&&fp_c2&&fp_c3){
		/*fseek(fp_s, 0, SEEK_END); 
		long s_len = ftell(fp_s);
		rewind(fp_s);*/

		fseek(fp_c1, 0, SEEK_END); 
		long c1_len = ftell(fp_c1);
		rewind(fp_c1);

		fseek(fp_c2, 0, SEEK_END); 
		long c2_len = ftell(fp_c2);
		rewind(fp_c2);

		fseek(fp_c3, 0, SEEK_END); 
		long c3_len = ftell(fp_c3);
		rewind(fp_c3);
		

		//char *s_bytes = malloc(s_len * sizeof( char));
		char *c1_bytes = malloc(c1_len * sizeof( char));
		
		char *c3_bytes = malloc(c3_len * sizeof( char));
		

		/*fread(s_bytes, s_len, 1, fp_s);
		fclose(fp_s);
		element_from_bytes_compressed(s,s_bytes);
		free(s_bytes);
		element_printf("s : %B\n\n", s);*/

		fread(c1_bytes, c1_len, 1, fp_c1);
		fclose(fp_c1);
		element_from_bytes_compressed(c1,c1_bytes);
		free(c1_bytes);
		element_printf("c1 : %B\n\n", c1);

		fread(c2, c2_len, 1, fp_c2);
		fclose(fp_c2);
		printf("c2 : %s\n\n", c2);


		fread(c3_bytes, c3_len, 1, fp_c3);
		fclose(fp_c3);
		element_from_bytes_compressed( c3,c3_bytes);
		free(c3_bytes);
		element_printf("c3 : %B\n\n", c3);


		
		
		

		
	}
}

int main(int argc, char const *argv[]){
	

	if(makeSocket()){
		printf("Reciever socket made successfuly\n");
	}

	getGlobalSetup();
	KeyGenR();
	connectToServer();
	msg = "pkr_set";
	send(server_socket,msg,strlen(msg),0);
	memset(buffer,0,sizeof buffer);



	while(1){
		if ((new_socket = accept(reciever_fd, (struct sockaddr *)&reciever_address,
					(socklen_t*)&reciever_addrlen))<0)
		{
			perror("accept");
			exit(EXIT_FAILURE);
		}else{
			valread = read( new_socket , id_buffer, 1024);
			
	   		if(strcmp(id_buffer,"peks_ct")==0){
	   			printf("Sender sending CT\n");

	   			getPEKS();

	   		}
		}


	}
	
	
	

	

	
	
	return 0;
}