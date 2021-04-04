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
pairing_t e;

char c2[]="";

int server_fd, new_socket, valread;
struct sockaddr_in server_address,sender_address,reciever_address;
int opt = 1;
int server_addrlen = sizeof(server_address),sender_addrlen = sizeof(sender_address),reciever_addrlen = sizeof(reciever_address);
char id_buffer[1024] = {0},secret_buffer[1024] = {0};



int sender_socket = 0,server_socket = 0,reciever_socket, valread;
char *msg = "sender|connect|nan";
char buffer[4096*8*10] = {0};


void GlobalSetup()
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
	
	


	element_random(g);
	element_random(g1);
	element_random(u);
	element_random(v);
	element_random(d);
	element_random(h);
	element_random(sks);
	element_pow_zn(pks, g, sks);

	//element_printf("g : %B\n", g);

	element_printf("g : %B\n\n", g);
	element_printf("g1 : %B\n\n", g1);
	element_printf("u : %B\n\n", u);
	element_printf("v : %B\n\n", v);
	element_printf("d : %B\n\n", d);
	element_printf("h : %B\n\n", h);
	element_printf("Sks = %B\n",sks);
	element_printf("Pks = %B\n",pks);
	


	

	FILE *fp_g,*fp_g1,*fp_u,*fp_v,*fp_d,*fp_h,*fp_pks ;
	fp_g = fopen("global_setup/g.txt", "w") ;
	fp_g1 = fopen("global_setup/g1.txt", "w") ;
	fp_u = fopen("global_setup/u.txt", "w") ;
	fp_v = fopen("global_setup/v.txt", "w") ;
	fp_d = fopen("global_setup/d.txt", "w") ;
	fp_h = fopen("global_setup/h.txt", "w") ;
	fp_pks = fopen("global_setup/pks.txt", "w") ;


	if(fp_g&&fp_g1&&fp_u&&fp_v&&fp_d&&fp_h&&fp_pks){
		int g_len = element_length_in_bytes_compressed(g);
		int g1_len = element_length_in_bytes_compressed(g1);
		int u_len = element_length_in_bytes_compressed(u);
		int v_len = element_length_in_bytes_compressed(v);
		int d_len = element_length_in_bytes_compressed(d);
		int h_len = element_length_in_bytes_compressed(h);
		int pks_len = element_length_in_bytes_compressed(pks);

		char *g_bytes = malloc(g_len * sizeof( char));
		char *g1_bytes = malloc(g1_len * sizeof( char));
		char *u_bytes = malloc(u_len * sizeof( char));
		char *v_bytes = malloc(v_len * sizeof( char));
		char *d_bytes = malloc(d_len * sizeof( char));
		char *h_bytes = malloc(h_len * sizeof( char));
		char *pks_bytes = malloc(pks_len * sizeof( char));
		

		

		element_to_bytes_compressed(g_bytes, g);
		element_to_bytes_compressed(g1_bytes, g1);
		element_to_bytes_compressed(u_bytes, u);
		element_to_bytes_compressed(v_bytes, v);
		element_to_bytes_compressed(d_bytes, d);
		element_to_bytes_compressed(h_bytes, h);
		element_to_bytes_compressed(pks_bytes, pks);
		


		


		fputs(g_bytes, fp_g) ;   
	    fputs("\n", fp_g) ;
	    fclose(fp_g) ;
	    free(g_bytes);

	    fputs(g1_bytes, fp_g1) ;   
	    fputs("\n", fp_g1) ;
	    fclose(fp_g1) ;
	    free(g1_bytes);

	    fputs(u_bytes, fp_u) ;   
	    fputs("\n", fp_u) ;
	    fclose(fp_u) ;
	    free(u_bytes);

	    fputs(v_bytes, fp_v) ;   
	    fputs("\n", fp_v) ;
	    fclose(fp_v) ;
	    free(v_bytes);

	    fputs(d_bytes, fp_d) ;   
	    fputs("\n", fp_d) ;
	    fclose(fp_d) ;
	    free(d_bytes);

	    fputs(h_bytes, fp_h) ;   
	    fputs("\n", fp_h) ;
	    fclose(fp_h) ;
	    free(h_bytes);

	    fputs(pks_bytes, fp_pks) ;   
	    fputs("\n", fp_pks) ;
	    fclose(fp_pks) ;
	    free(pks_bytes);
	    printf("PKS written\n");

	    printf("Global setup written\n");
	}else{
		printf("File open error\n");
	}	
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

void getPKR(){

	element_init_G1(pkr,e);
	FILE *fp_pkr ;
	fp_pkr = fopen("global_setup/pkr.txt", "rb") ;
	if(fp_pkr){
		fseek(fp_pkr, 0, SEEK_END); 
		long pkr_len = ftell(fp_pkr);
		rewind(fp_pkr);
		char *pkr_bytes = malloc(pkr_len * sizeof( char));

		fread(pkr_bytes, pkr_len, 1, fp_pkr);
		fclose(fp_pkr);
		element_from_bytes_compressed(pkr, pkr_bytes);
		free(pkr_bytes);
		element_printf("pkr : %B\n\n", pkr);

	}
}

int makeSocket(){
	printf("SOCKET INITIALIZATION\n");
	if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
	{
		perror("socket failed");
		exit(EXIT_FAILURE);
	}
	
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
												&opt, sizeof(opt)))
	{
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}
	server_address.sin_family = AF_INET;
	server_address.sin_addr.s_addr = INADDR_ANY;
	server_address.sin_port = htons( SERVER_PORT );
	
	if (bind(server_fd, (struct sockaddr *)&server_address,
								sizeof(server_address))<0)
	{
		perror("bind failed");
		exit(EXIT_FAILURE);
	}
	if (listen(server_fd, 3) < 0)
	{
		perror("listen");
		exit(EXIT_FAILURE);
	}
	return 1;
}

int connectToSender(){

	if ((sender_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		printf("\n Socket creation error \n");
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

int connectToReciever(){

	if ((reciever_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		printf("\n Socket creation error \n");
		return -1;
	}

	reciever_address.sin_family = AF_INET;
	reciever_address.sin_port = htons(RECIEVER_PORT);
	
	// Convert IPv4 and IPv6 addresses from text to binary form
	if(inet_pton(AF_INET, "127.0.0.1", &reciever_address.sin_addr)<=0)
	{
		printf("\nInvalid address/ Address not supported \n");
		return -1;
	}

	if (connect(reciever_socket, (struct sockaddr *)&reciever_address, sizeof(reciever_address)) < 0)
	{
		printf("\nConnection to reciever failed \n");
		return -1;
	}
	return 1;
}


int main(int argc, char const *argv[]){
	
	GlobalSetup();
	
	if(makeSocket()){
		printf("Server socket made successfuly\n");
	}

	while(1){
		if ((new_socket = accept(server_fd, (struct sockaddr *)&server_address,
					(socklen_t*)&server_addrlen))<0)
		{
			perror("accept");
			exit(EXIT_FAILURE);
		}else{
			valread = read( new_socket , id_buffer, 1024);
			
	   		if(strcmp(id_buffer,"pkr_set")==0){
	   			getPKR();
	   			printf("Got pkr\n");

	   		}
	   		if(strcmp(id_buffer,"peks_ct")==0){
	   			printf("Sender sending CT\n");

	   			getPEKS();

	   		}
		}


	}
	
	return 0;
}