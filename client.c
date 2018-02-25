#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define HOST "localhost"
#define PORT 8765

/* use these strings to tell the marker what is happening */
#define FMT_CONNECT_ERR "ECE568-CLIENT: SSL connect error\n"
#define FMT_SERVER_INFO "ECE568-CLIENT: %s %s %s\n"
#define FMT_OUTPUT "ECE568-CLIENT: %s %s\n"
#define FMT_CN_MISMATCH "ECE568-CLIENT: Server Common Name doesn't match\n"
#define FMT_EMAIL_MISMATCH "ECE568-CLIENT: Server Email doesn't match\n"
#define FMT_NO_VERIFY "ECE568-CLIENT: Certificate does not verify\n"
#define FMT_INCORRECT_CLOSE "ECE568-CLIENT: Premature close\n"

int password_cb(char *buf, int size, int rwflag, void *password)
{
    printf("here!");
    strncpy(buf, (char *)(password), size);
    buf[size - 1] = '\0';
    return strlen(buf);
}

SSL_CTX* InitCTX()
{   
    const SSL_METHOD *method;
    SSL_CTX *ctx;
 
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    method = SSLv23_method();  /* Create new client-method instance */
    ctx = SSL_CTX_new(method);   /* Create new context */


    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }



    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER,NULL);



    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_1);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_2);
    SSL_CTX_set_cipher_list(ctx, "SHA1");

    char *keyfile="alice.pem";
    //char *password="password";

    SSL_CTX_set_default_passwd_cb_userdata(ctx, (void*)"password");
    /* Load local key and certificate*/
    if ( SSL_CTX_use_certificate_file(ctx, keyfile, SSL_FILETYPE_PEM) <= 0 ){
      //ERR_print_errors_fp("Can't read certificate file");
      abort();
    }

    
    if ( SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM) <= 0 ){
      //ERR_print_errors_fp("Can't read key file");
      //abort();
	SSL_CTX_set_default_passwd_cb_userdata(ctx, (void*)"password");
    }


    //Load the CA that the client trusts
    if ( SSL_CTX_load_verify_locations(ctx, "568ca.pem", NULL) <= 0 ){    
      //ERR_print_errors_fp("Can't read CA certificate");
      abort();
    }

    return ctx;
}



int main(int argc, char **argv)
{


  int len, sock, port=PORT;
  char *host=HOST;
  struct sockaddr_in addr;
  struct hostent *host_entry;
  char buf[256];
  char *secret = "What's the question?";
  
  /*Parse command line arguments*/
  
  switch(argc){
    case 1:
      break;
    case 3:
      host = argv[1];
      port=atoi(argv[2]);
      if (port<1||port>65535){
	fprintf(stderr,"invalid port number");
	exit(0);
      }
      break;
    default:
      printf("Usage: %s server port\n", argv[0]);
      exit(0);
  }
  
  /*get ip address of the host*/
  
  host_entry = gethostbyname(host);
  
  if (!host_entry){
    fprintf(stderr,"Couldn't resolve host");
    exit(0);
  }

  memset(&addr,0,sizeof(addr));
  addr.sin_addr=*(struct in_addr *) host_entry->h_addr_list[0];
  addr.sin_family=AF_INET;
  addr.sin_port=htons(port);
  
  printf("Connecting to %s(%s):%d\n", host, inet_ntoa(addr.sin_addr),port);
  
  /*open socket*/
  
  if((sock=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))<0)
    perror("socket");
  if(connect(sock,(struct sockaddr *)&addr, sizeof(addr))<0)
    perror("connect");

  SSL_library_init();
  SSL_CTX *ctx;
  SSL *ssl;
  ctx = InitCTX();
  ssl=SSL_new(ctx);

  SSL_set_fd(ssl, sock); //attach the socket descriptor
  if(SSL_connect(ssl)<=0){
	fprintf(stderr,FMT_CONNECT_ERR);
	ERR_print_errors_fp(stderr);
  	exit(0);
  }

  X509 *peer;
  char peer_CN[256];
  
  
  /*Check the common name*/
  peer=SSL_get_peer_certificate(ssl);


  if(SSL_get_verify_result(ssl)!=X509_V_OK){
	fprintf(stderr,FMT_NO_VERIFY);    
	exit(0);
  }
  /*Check the cert chain. The chain length
  is automatically checked by OpenSSL when
  we set the verify depth in the ctx */




  X509_NAME_get_text_by_NID(X509_get_subject_name(peer),NID_commonName, peer_CN, 256);
  int CN_check = strcasecmp(peer_CN,"Bob's Server"); //0 means the CN is correct

  char peer_email[256];
  X509_NAME_get_text_by_NID(X509_get_subject_name(peer), OBJ_txt2nid("emailAddress"), peer_email, 256);
  int email_check = strcasecmp(peer_email,"ece568bob@ecf.utoronto.ca"); //0 means the email is correct

  if(CN_check!=0){
        //printf("common name = %s\n",peer_CN);
	fprintf(stderr,FMT_CN_MISMATCH);    
	exit(0);
  }
  if(email_check!=0){
	fprintf(stderr,FMT_EMAIL_MISMATCH);    
	exit(0);
  }


  char certificate_issuer[256];
  X509_NAME_get_text_by_NID(X509_get_issuer_name(peer), NID_commonName, certificate_issuer, 256);
  printf(FMT_SERVER_INFO, peer_CN, peer_email, certificate_issuer);
  

  SSL_write(ssl, secret, strlen(secret));
  len=SSL_read(ssl,buf,256);
  buf[len]='\0';
  printf(FMT_OUTPUT, secret, buf);

  /*
  send(sock, secret, strlen(secret),0);
  len = recv(sock, &buf, 255, 0);
  buf[len]='\0';
  */
  /* this is how you output something for the marker to pick up */
  //printf(FMT_OUTPUT, secret, buf);
  

  /*
  while(1){
	printf("wait here before exit until you input -1: ");
	int x;
	scanf("%d",&x);
	break;
  }*/

  //uncomment the following line to test whether the client side can detect improper shutdown
  //return 0;

  int r=SSL_shutdown(ssl);
  if(!r){
  /* If we called SSL_shutdown() first then
     we always get return value of '0'. In
     this case, try again, but first send a
     TCP FIN to trigger the other side's
     close_notify*/
  shutdown(sock,1);
  r=SSL_shutdown(ssl);
  }

  switch(r){
  case 1:
    break; /* Success */
  default:
  {
	fprintf(stderr,FMT_INCORRECT_CLOSE);
	abort();
  }
  }

  close(sock);
  return 1;
}
