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



element_t g,g1,u,v,d,h,sks,skr,pks,pkr,C1,C3,S;
pairing_t e;
unsigned char c2[]="";

int server_fd, new_socket, valread,sender_fd;
struct sockaddr_in server_address,sender_address,reciever_address;
int opt = 1;
int server_addrlen = sizeof(server_address),sender_addrlen = sizeof(sender_address),reciever_addrlen = sizeof(reciever_address);
char id_buffer[1024] = {0},secret_buffer[1024] = {0};

char *prev_sender = "nan",*prev_token = "nan";
int serverConnected = -1,senderConnected = -1,recieverConnected = -1;



int sender_socket = 0,server_socket = 0,reciever_socket=0, valread;
char *msg = "sender|connect|nan";
char buffer[4096*8*10] = {0};




void H2(element_t in, unsigned char c2[], element_t out)
{
	unsigned char buffer[130]="";
	for(int i=0;i<strlen(c2);i=i+4)
	{
		unsigned char str[5]={'\0'};
		str[0]=c2[i];
		str[1]=c2[i+1];
		str[2]=c2[i+2];
		str[3]=c2[i+3];
		
		if(!strcmp(str,"0000"))
		{
			strcat(buffer,"0");
		}
		else if(!strcmp(str,"0001"))
		{
			strcat(buffer,"1");
		}
		else if(!strcmp(str,"0010"))
		{
			strcat(buffer,"2");
		}
		else if(!strcmp(str,"0011"))
		{
			strcat(buffer,"3");
		}
		else if(!strcmp(str,"0100"))
		{
			strcat(buffer,"4");
		}
		else if(!strcmp(str,"0101"))
		{
			strcat(buffer,"5");
		}
		else if(!strcmp(str,"0110"))
		{
			strcat(buffer,"6");
		}
		else if(!strcmp(str,"0111"))
		{
			strcat(buffer,"7");
		}
		else if(!strcmp(str,"1000"))
		{
			strcat(buffer,"8");
		}
		else if(!strcmp(str,"1001"))
		{
			strcat(buffer,"9");
		}
		else if(!strcmp(str,"1010"))
		{
			strcat(buffer,"a");
		}
		else if(!strcmp(str,"1011"))
		{
			strcat(buffer,"b");
		}
		else if(!strcmp(str,"1100"))
		{
			strcat(buffer,"c");
		}
		else if(!strcmp(str,"1101"))
		{
			strcat(buffer,"d");
		}
		else if(!strcmp(str,"1110"))
		{
			strcat(buffer,"e");
		}
		else if(!strcmp(str,"1111"))
		{
			strcat(buffer,"f");
		}
	}
	unsigned char buffer1[130],out_buf[130];
    unsigned char buffer_sha512[130];
    int x = 0xFF;
    memset(buffer_sha512, '\0', 128);
    element_to_bytes(buffer1, in);
    SHA512(buffer1,element_length_in_bytes(in),buffer_sha512);

	int z = PKCS5_PBKDF2_HMAC_SHA1(buffer_sha512, 128, buffer, 128, 1, 64, out_buf);
	element_from_bytes(out,out_buf);
}


void H1(element_t G1_in, unsigned char c2[])
{
  	unsigned char buffer[130],str[SHA512_DIGEST_LENGTH*2];
  	char c[3] = {'\0'};
  	char ch;
	unsigned char buffer_sha512[130];
  	int x = 0xFF;
  	memset(buffer_sha512, '\0', 128);
  	element_to_bytes(buffer, G1_in);
	int i,j;
	SHA512(buffer, element_length_in_bytes(G1_in), buffer_sha512);
	for(i = 0,j=0; i < SHA512_DIGEST_LENGTH; ++i,j=j+2) {
	   sprintf(c,"%x",buffer_sha512[i]);
	   str[j]=c[0];
	   /*if(c[1]!='\0')
	   {
	   		str[j+1]=c[1];
	   }
	   else
	   {
	   		j--;
	   }*/
	   str[j+1]=c[1];
	   if(i==0)
	   {
	   	ch=c[0];
	   }
	   //printf("%x", buffer_sha512[i]);
	}
	//printf("\n");
	str[0]=ch;
	for(i = 0; i < SHA512_DIGEST_LENGTH*2; ++i) {
		
	   //printf("%c", str[i]);
	   switch(str[i])
	   {
	   		case '0':strcat(c2,"0000");break;
	   		case '1':strcat(c2,"0001");break;
	   		case '2':strcat(c2,"0010");break;
	   		case '3':strcat(c2,"0011");break;
	   		case '4':strcat(c2,"0100");break;
	   		case '5':strcat(c2,"0101");break;
	   		case '6':strcat(c2,"0110");break;
	   		case '7':strcat(c2,"0111");break;
	   		case '8':strcat(c2,"1000");break;
	   		case '9':strcat(c2,"1001");break;
	   		case 'a':strcat(c2,"1010");break;
	   		case 'b':strcat(c2,"1011");break;
	   		case 'c':strcat(c2,"1100");break;
	   		case 'd':strcat(c2,"1101");break;
	   		case 'e':strcat(c2,"1110");break;
	   		case 'f':strcat(c2,"1111");break;
	   		default : break;
	   	}
	   
	}
	
	printf("\n");
}

void H(element_t IB_e_GT_in,element_t IB_e_G1_out)
{
  unsigned char buffer[130];
  unsigned char buffer_sha512[130];
  int x = 0xFF;
  memset(buffer_sha512, '\0', 128);
  element_to_bytes(buffer, IB_e_GT_in);
  SHA512(buffer,element_length_in_bytes(IB_e_GT_in),buffer_sha512);

  element_from_hash(IB_e_G1_out, buffer_sha512, 64);
}


void getGlobalSetupAndKeys(){
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

	element_init_G1(pks,e);
	element_init_G1(pkr,e);
	
	


	


	

	FILE *fp_g,*fp_g1,*fp_u,*fp_v,*fp_d,*fp_h,*fp_pks,*fp_pkr ;

	
	fp_g = fopen("global_setup/g.txt", "rb") ;
	fp_g1 = fopen("global_setup/g1.txt", "rb") ;
	fp_u = fopen("global_setup/u.txt", "rb") ;
	fp_v = fopen("global_setup/v.txt", "rb") ;
	fp_d = fopen("global_setup/d.txt", "rb") ;
	fp_h = fopen("global_setup/h.txt", "rb") ;
	fp_pks = fopen("global_setup/pks.txt", "rb") ;
	fp_pkr = fopen("global_setup/pkr.txt", "rb") ;


	if(fp_g&&fp_g1&&fp_u&&fp_v&&fp_d&&fp_h&&fp_pks&&fp_pkr){

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

		fseek(fp_pkr, 0, SEEK_END); 
		long pkr_len = ftell(fp_pkr);
		rewind(fp_pkr);




		char *g_bytes = malloc(g_len * sizeof( char));
		char *g1_bytes = malloc(g1_len * sizeof( char));
		char *u_bytes = malloc(u_len * sizeof( char));
		char *v_bytes = malloc(v_len * sizeof( char));
		char *d_bytes = malloc(d_len * sizeof( char));
		char *h_bytes = malloc(h_len * sizeof( char));
		char *pks_bytes = malloc(pks_len * sizeof( char));
		char *pkr_bytes = malloc(pkr_len * sizeof( char));

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

		fread(pkr_bytes, pkr_len, 1, fp_pkr);
		fclose(fp_pkr);
		element_from_bytes_compressed(pkr, pkr_bytes);
		free(pkr_bytes);
		element_printf("pkr : %B\n\n", pkr);

	}
	
}


int makeSocket(){
	printf("SOCKET INITIALIZATION\n");
	if ((sender_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
	{
		perror("socket failed");
		exit(EXIT_FAILURE);
	}
	
	if (setsockopt(sender_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
												&opt, sizeof(opt)))
	{
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}
	sender_address.sin_family = AF_INET;
	sender_address.sin_addr.s_addr = INADDR_ANY;
	sender_address.sin_port = htons( SENDER_PORT );
	
	if (bind(sender_fd, (struct sockaddr *)&sender_address,
								sizeof(sender_address))<0)
	{
		perror("bind failed");
		exit(EXIT_FAILURE);
	}
	if (listen(sender_fd, 3) < 0)
	{
		perror("listen");
		exit(EXIT_FAILURE);
	}
	return 1;
}

int connectToServer(){

	if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		printf("\n Socket creation error \n");
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
		server_socket = 0;
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

int retryToServer(){
	if (connect(server_socket, (struct sockaddr *)&server_address, sizeof(server_address)) < 0)
	{
		printf("\nConnection to server failed \n");
		return -1;
	}
	return 1;
}

int retryToReciever(){
	if (connect(reciever_socket, (struct sockaddr *)&reciever_address, sizeof(reciever_address)) < 0)
	{
		printf("\nConnection to reciever failed \n");
		return -1;
	}
	return 1;
}

void PKES(){
	char c2[1024]={0};
	element_t c1,ct,r,s,t,tr,g1w,g1wh,w,h1,uh1,vs,vsd,c3,c3_r;
	element_init_G1(c1, e);
	
	element_init_G1(ct, e);
	element_init_G1(g1w,e);
	element_init_G1(g1wh,e);
	element_init_G1(uh1,e);
	element_init_G1(vs,e);
	element_init_G1(vsd,e);
	element_init_G1(c3,e);
	element_init_G1(c3_r,e);
	element_init_GT(t, e);
	element_init_GT(tr, e);
	element_init_Zr(h1,e);
	element_init_Zr(r,e);
	element_init_Zr(s,e);
	element_init_Zr(w,e);


	element_random(w);
	element_random(r);
	element_random(s);

	//c1 = pkr^r
	element_pow_zn(c1, pkr, r);
	//g1w = g1^w
	element_pow_zn(g1w,g1,w);
	//g1wh = g1w*h
	element_mul(g1wh,g1w,h);
	//t = pks X g1wh
	pairing_apply(t, pks, g1wh, e);
	//tr = t^r
	element_pow_zn(tr,t,r);
	//c2 = H1(tr)
	H1(tr,c2);
	//h1 = H2(c1,c2)
	H2(c1,c2,h1);
	//uh1 = u^h1
	element_pow_zn(uh1,u,h1);
	//vs = v^s
	element_pow_zn(vs,v,s);
	//vsd = vs*d
	element_mul(vsd,vs,d);
	//c3 = uh1*vsd
	element_mul(c3,uh1,vsd);
	//c3_r = c3^r
	element_pow_zn(c3_r,c3,r);


	element_printf("r = %B\n",r);
	element_printf("s = %B\n",s);
	element_printf("c1 = %B\n",c1);
	element_printf("tr = %B\n",tr);
	printf("c2 : %s\n",c2);
	element_printf("h1 = %B\n",h1);
	element_printf("c3 = %B\n",c3_r);


	

	
	FILE *fp_s,*fp_c1,*fp_c2,*fp_c3 ;
	fp_s= fopen("global_setup/s.txt", "w") ;
	fp_c1 = fopen("global_setup/c1.txt", "w") ;
	fp_c2= fopen("global_setup/c2.txt", "w") ;
	fp_c3 = fopen("global_setup/c3.txt", "w") ;
	


	printf("Files pointer created\n");
	if(fp_s&&fp_c1&&fp_c2&&fp_c3){
		int s_len = element_length_in_bytes_compressed(s);
		int c1_len = element_length_in_bytes_compressed(c1);
		int c3_len = element_length_in_bytes_compressed(c3);

		printf("Element length taken s : %d c1 : %d c3 : %d\n",s_len,c1_len,c3_len);
		

		//char *s_bytes = malloc(s_len * sizeof( char));
		char *c1_bytes = malloc(c1_len * sizeof( char));
		char *c3_bytes = malloc(c3_len * sizeof( char));

		printf("bytes created\n");
		

		element_to_bytes_compressed(c1_bytes, c1);
		printf("c1 compressed\n");
		element_to_bytes_compressed(c3_bytes, c3);
		printf("c3 compressed\n");
		//element_to_bytes_compressed(s_bytes, s);
		//printf("s compressed\n");
		
		

		printf("Element compressed\n");

		/*fputs(s_bytes, fp_s) ;   
	    fputs("\n", fp_s) ;
	    fclose(fp_s) ;
	    free(s_bytes);*/

	    fputs(c1_bytes, fp_c1) ;   
	    fputs("\n", fp_c1) ;
	    fclose(fp_c1) ;
	    free(c1_bytes);

	    fputs(c2, fp_c2) ;   
	    fputs("\n", fp_c2) ;
	    fclose(fp_c2) ;
	    

	    fputs(c3_bytes, fp_c3) ;   
	    fputs("\n", fp_c3) ;
	    fclose(fp_c3) ;
	    free(c3_bytes);
	}
	

	connectToServer();
	msg = "peks_ct";
	send(server_socket,msg,strlen(msg),0);
	memset(buffer,0,sizeof buffer);

	connectToReciever();
	msg = "peks_ct";
	send(reciever_socket,msg,strlen(msg),0);
	memset(buffer,0,sizeof buffer);




}

int main(int argc, char const *argv[]){
	

	if(makeSocket()){
		printf("Sender socket made successfuly\n");
	}

	getGlobalSetupAndKeys();
	PKES();

	
	return 0;
}