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

#define PORT 8765

/* use these strings to tell the marker what is happening */
#define FMT_ACCEPT_ERR "ECE568-SERVER: SSL accept error\n"
#define FMT_CLIENT_INFO "ECE568-SERVER: %s %s\n"
#define FMT_OUTPUT "ECE568-SERVER: %s %s\n"
#define FMT_INCOMPLETE_CLOSE "ECE568-SERVER: Incomplete shutdown\n"

SSL_CTX* InitCTX_Server()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;


    SSL_library_init();
    SSL_load_error_strings();

    method = SSLv23_method();  /* Create new client-method instance */
    ctx = SSL_CTX_new(method);   /* Create new context */


    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }


    SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_1);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_2);
    SSL_CTX_set_cipher_list(ctx, "ALL");


    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_CLIENT_ONCE,NULL);


    char *keyfile="bob.pem";
    //char *password="password";
    SSL_CTX_set_default_passwd_cb_userdata(ctx, (void*)"password");

    /* Load local key and certificate*/
    if ( SSL_CTX_use_certificate_file(ctx, keyfile, SSL_FILETYPE_PEM) <= 0 ){
      //ERR_print_errors_fp("Can't read certificate file");
      abort();
    }

    //passphrase=password
    if ( SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM) <= 0 ){
      //ERR_print_errors_fp("Can't read key file");
      abort();
    }


    //Load the CA that the client trusts
    if ( SSL_CTX_load_verify_locations(ctx, "568ca.pem", NULL) <= 0 ){
      //ERR_print_errors_fp("Can't read CA certificate");
      abort();
    }

    SSL_CTX_set_verify_depth(ctx,1);

    return ctx;
}





int main(int argc, char **argv)
{

  SSL_CTX *ctx;
  ctx = InitCTX_Server();

  int s, sock, port=PORT;
  struct sockaddr_in sin;
  int val=1;
  pid_t pid;

  /*Parse command line arguments*/

  switch(argc){
    case 1:
      break;
    case 2:
      port=atoi(argv[1]);
      if (port<1||port>65535){
	fprintf(stderr,"invalid port number");
	exit(0);
      }
      break;
    default:
      printf("Usage: %s port\n", argv[0]);
      exit(0);
  }

  if((sock=socket(AF_INET,SOCK_STREAM,0))<0){
    perror("socket");
    close(sock);
    exit(0);
  }

  memset(&sin,0,sizeof(sin));
  sin.sin_addr.s_addr=INADDR_ANY;
  sin.sin_family=AF_INET;
  sin.sin_port=htons(port);

  setsockopt(sock,SOL_SOCKET,SO_REUSEADDR, &val,sizeof(val));

  if(bind(sock,(struct sockaddr *)&sin, sizeof(sin))<0){
    perror("bind");
    close(sock);
    exit (0);
  }

  if(listen(sock,5)<0){
    perror("listen");
    close(sock);
    exit (0);
  }

  while(1){

    if((s=accept(sock, NULL, 0))<0){
      perror("accept");
      close(sock);
      close(s);
      exit (0);
    }

    /*fork a child to handle the connection*/

    if((pid=fork())){
      close(s);
    }
    else {
      /*Child code*/
      int len;
      char buf[256];
      char *answer = "42";

      BIO *sbio=BIO_new_socket(s, BIO_NOCLOSE);
      SSL *ssl=SSL_new(ctx);
      SSL_set_bio(ssl,sbio,sbio);

      if(SSL_accept(ssl) <= 0){
        
        fprintf(stderr,FMT_ACCEPT_ERR);
        ERR_print_errors_fp(stderr);
        exit(0);
      }

      X509 *peer=NULL;
      /*
      if(SSL_get_verify_result(ssl)!=X509_V_OK){
	printf("here2\n");
           fprintf(stderr,FMT_ACCEPT_ERR);
           ERR_print_errors_fp(stderr);
           exit(0);
      }*/

      peer=SSL_get_peer_certificate(ssl);
      if (peer==NULL){
	
        //printf("cannot get peer certificate\n");
        fprintf(stderr,FMT_ACCEPT_ERR);
        ERR_print_errors_fp(stderr);
        exit(0);
      }
      //The client's certificate is not issued by recgonized CA
      if(SSL_get_verify_result(ssl)!=X509_V_OK){
	   printf("client's certificate verification fails\n");
    	   fprintf(stderr,FMT_ACCEPT_ERR);
           ERR_print_errors_fp(stderr);
    	   exit(0);
      }

      //get the common name of the customer
      char peer_CN[256];
      X509_NAME_get_text_by_NID(X509_get_subject_name(peer),NID_commonName, peer_CN, 256);

      //get the common name of the customer
      char peer_email[256];
      X509_NAME_get_text_by_NID(X509_get_subject_name(peer), OBJ_txt2nid("emailAddress"), peer_email, 256);
      printf(FMT_CLIENT_INFO, peer_CN,peer_email);

      len=SSL_read(ssl, buf, 256);
      buf[len]= '\0';
      printf(FMT_OUTPUT, buf, answer);
      /*
      len = recv(s, &buf, 255, 0);
      buf[len]= '\0';
      printf(FMT_OUTPUT, buf, answer);
      send(s, answer, strlen(answer), 0);
      */
      SSL_write(ssl, answer, strlen(answer));

      //uncomment the following line to test whether the client side can detect improper shutdown
      //return 0;

      int r=SSL_shutdown(ssl);
      if(!r){
        /* If we called SSL_shutdown() first then
           we always get return value of '0'. In
           this case, try again, but first send a
           TCP FIN to trigger the other side's
           close_notify*/
        shutdown(s,1);
        r=SSL_shutdown(ssl);
      }
      switch(r){
        case 1:
          break; /* Success */
        //case 0:
        //case -1:
        default:
        {
          fprintf(stderr,FMT_INCOMPLETE_CLOSE);
          exit(0);
        }
      }





      SSL_free(ssl);
      close(sock);
      close(s);
      return 0;
    }
  }

  close(sock);
  return 1;
}
