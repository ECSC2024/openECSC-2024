#include "tlse/tlse.c"

#include <stdio.h>
#include <string.h> //strlen
#include <sys/socket.h>
#include <arpa/inet.h>

static char identity_str[0xFF] = {0};

static char current_subject[0xFF] = {0};

static char issuer[0xFF] = {0};

int read_from_file(const char *fname, void *buf, int max_len)
{
    FILE *f = fopen(fname, "rb");
    if (f)
    {
        int size = fread(buf, 1, max_len - 1, f);
        if (size > 0)
            ((unsigned char *)buf)[size] = 0;
        else
            ((unsigned char *)buf)[0] = 0;
        fclose(f);
        return size;
    }
    return 0;
}

void load_keys(struct TLSContext *context, char *fname, char *priv_fname)
{
    unsigned char buf[0xFFFF];
    unsigned char buf2[0xFFFF];
    int size = read_from_file(fname, buf, 0xFFFF);
    int size2 = read_from_file(priv_fname, buf2, 0xFFFF);
    if (size > 0)
    {
        if (context)
        {
            tls_load_certificates(context, buf, size);
            tls_load_private_key(context, buf2, size2);
        }
    }
}

int send_pending(int client_sock, struct TLSContext *context)
{
    unsigned int out_buffer_len = 0;
    const unsigned char *out_buffer = tls_get_write_buffer(context, &out_buffer_len);
    unsigned int out_buffer_index = 0;
    int send_res = 0;
    while ((out_buffer) && (out_buffer_len > 0))
    {
        int res = write(client_sock, (char *)&out_buffer[out_buffer_index], out_buffer_len);
        if (res <= 0)
        {
            send_res = res;
            break;
        }
        out_buffer_len -= res;
        out_buffer_index += res;
    }
    tls_buffer_clear(context);
    return send_res;
}

int verify_signature(struct TLSContext *context, struct TLSCertificate **certificate_chain, int len) {
    int i;
    int err;
    if (certificate_chain) {
        for (i = 0; i < len; i++) {
            struct TLSCertificate *certificate = certificate_chain[i];
            err = tls_certificate_is_valid(certificate);
            if (err)
                return err;
        }
    }
    err = tls_certificate_chain_is_valid(certificate_chain, len);
    if (err)
        return err;

    const char *sni = tls_sni(context);
    if ((len > 0) && (sni)) {
        err = tls_certificate_valid_subject(certificate_chain[0], sni);
        if (err)
            return err;
    }

    err = tls_certificate_chain_is_valid_root(context, certificate_chain, len);
    if (err)
        return err;

    fprintf(stderr, "Certificate signature OK\n");

    struct TLSCertificate *cert = certificate_chain[0];
        if (cert)
        {
            if(cert->subject==NULL){
                fprintf(stderr, "Certificate subject NOT OK\n");
                return certificate_unknown;
            }
            if(cert->issuer_entity==NULL){
                fprintf(stderr, "Certificate issuer NOT OK\n");
                return certificate_unknown;
            }
            strncpy(current_subject, cert->subject, 0xFE);
            strncpy(issuer, cert->issuer_entity, 0xFE);
            fprintf(stderr, "Verified: %s\n", identity_str);
        }else{
            return certificate_unknown;
        }
    return no_error;
}


int main(int argc, char *argv[])
{

    struct TLSContext *server_context = tls_create_context(1, TLS_V12);
    char client_message[0xFFFF];
    ssize_t read_size;
    // load keys
    load_keys(server_context, "./flagsdistribution.com.pem", "./flagsdistribution.com.key");

    char source_buf[0xFFFF];
    struct TLSContext *context = tls_accept(server_context);

    SSL_CTX_root_ca(context, "./rootCACert.pem");

    tls_request_client_certificate(context);

    tls_make_exportable(context, 1);

    fprintf(stderr, "Client connected\n");
    while ((read_size = read(STDIN_FILENO, client_message, sizeof(client_message))) > 0)
    {
        int response = tls_consume_stream(context, client_message, read_size, verify_signature);
        if (response > 0)
            break;
    }
    send_pending(STDOUT_FILENO, context);
    if (read_size > 0)
    {
        int ref_packet_count = 0;
        int res;
        while ((read_size = read(STDIN_FILENO, client_message, sizeof(client_message))) > 0)
        {
            if (tls_consume_stream(context, client_message, read_size, verify_signature) < 0)
            {
                fprintf(stderr, "Error in stream consume\n");
                break;
            }
            send_pending(STDOUT_FILENO, context);
            if (tls_established(context) == 1)
            {
                unsigned char read_buffer[0xFFFF];
                unsigned char send_buffer[0xF000];
                if(strncmp(issuer, "Flags distribution Inc.", 24)!=0){
                    sprintf(send_buffer, "I see you are working for a competitor! %s's employees are not allowed to enter this system! Get OFF!\n", issuer);
                }else if(strncmp(current_subject, "FlagsDistributionAdministrator", 31)!=0){
                    sprintf(send_buffer, "Hello %s and welcome to the system! The system is currently being developed and is not yet available to all employees. Please contact your local IT administrator to gain access.\n", current_subject);
                }else{
                    char* flag = getenv("FLAG");
                    if(!flag){
                        sprintf(send_buffer, "Hello %s! Currently the only flag available in the system is openECSC{fakeflag}\n", current_subject);
                    }else{
                        sprintf(send_buffer, "Hello %s! Currently the only flag available in the system is %s\n", current_subject, flag);
                    }
                }
                tls_write(context, send_buffer, strlen(send_buffer));
                send_pending(STDOUT_FILENO, context);
                tls_close_notify(context);
                break;
            }
            send_pending(STDOUT_FILENO, context);
        }
    }
    tls_destroy_context(context);

    tls_destroy_context(server_context);
    return 0;
}
