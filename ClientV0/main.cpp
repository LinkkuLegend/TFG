/* 
 * File:   main.cpp
 * Author: Linkku
 *
 * Created on 21 de noviembre de 2014, 19:38
 */

//#define LIBSSH_STATIC 1

#include <cstdlib>
#include <iostream> //TODO hay que borrar esto
#include <fstream>
#include <libssh/libssh.h>
#include <sys/stat.h>
#include <dirent.h>


using namespace std;

inline bool existsFile(const string& name) {
    ifstream f(name.c_str());
    if (f.good()) {
        f.close();
        return true;
    } else {
        f.close();
        return false;
    }
}

int verify_knownhost(ssh_session session) {
    int state, hlen;
    unsigned char *hash = NULL;
    char *hexa;
    char buf[10];
    state = ssh_is_server_known(session);
    hlen = ssh_get_pubkey_hash(session, &hash);
    if (hlen < 0)
        return -1;
    switch (state) {
        case SSH_SERVER_KNOWN_OK:
            break; /* ok */
        case SSH_SERVER_KNOWN_CHANGED:
            fprintf(stderr, "Host key for server changed: it is now:\n");
            ssh_print_hexa("Public key hash", hash, hlen);
            fprintf(stderr, "For security reasons, connection will be stopped\n");
            free(hash);
            return -1;
        case SSH_SERVER_FOUND_OTHER:
            fprintf(stderr, "The host key for this server was not found but an other"
                    "type of key exists.\n");
            fprintf(stderr, "An attacker might change the default server key to"
                    "confuse your client into thinking the key does not exist\n");
            free(hash);
            return -1;
        case SSH_SERVER_FILE_NOT_FOUND:
            fprintf(stderr, "Could not find known host file.\n");
            fprintf(stderr, "If you accept the host key here, the file will be"
                    "automatically created.\n");
            /* fallback to SSH_SERVER_NOT_KNOWN behavior */
        case SSH_SERVER_NOT_KNOWN:
            hexa = ssh_get_hexa(hash, hlen);
            fprintf(stderr, "The server is unknown. Do you trust the host key?\n");
            fprintf(stderr, "Public key hash: %s\n", hexa);
            free(hexa);
            if (fgets(buf, sizeof (buf), stdin) == NULL) {
                free(hash);
                return -1;
            }
            if (strncasecmp(buf, "yes", 3) != 0) {
                free(hash);
                return -1;
            }
            if (ssh_write_knownhost(session) < 0) {
                fprintf(stderr, "Error %s\n", strerror(errno));
                free(hash);
                return -1;
            }
            break;
        case SSH_SERVER_ERROR:
            fprintf(stderr, "Error %s", ssh_get_error(session));
            free(hash);
            return -1;
    }
    free(hash);
    return 0;
}

int authenticate_pubkey(ssh_session session) {
    int rc;
    rc = ssh_userauth_publickey_auto(session, NULL, "Pablito");
    if (rc == SSH_AUTH_ERROR) {
        fprintf(stderr, "Authentication failed: %s\n", ssh_get_error(session));
        return SSH_AUTH_ERROR;
    }
    return rc;
}

int shell_session(ssh_session session) {

    ssh_channel channel;
    int rc;
    channel = ssh_channel_new(session);

    if (channel == NULL)
        return SSH_ERROR;
    rc = ssh_channel_open_session(channel);

    if (rc != SSH_OK) {
        ssh_channel_free(channel);
        return rc;
    }

    rc = ssh_channel_request_exec(channel, "ls -l");
    if (rc != SSH_OK) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return rc;
    }

    char buffer[256];
    unsigned int nbytes;
    nbytes = ssh_channel_read(channel, buffer, sizeof (buffer), 0);

    while (nbytes > 0) {
        if (fwrite(buffer, 1, nbytes, stdout) != nbytes) {
            ssh_channel_close(channel);
            ssh_channel_free(channel);
            return SSH_ERROR;
        }
        nbytes = ssh_channel_read(channel, buffer, sizeof (buffer), 0);
    }

    if (nbytes < 0) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return SSH_ERROR;
    }


    ssh_channel_close(channel);
    ssh_channel_send_eof(channel);
    ssh_channel_free(channel);
    return SSH_OK;

}

int scp_helloworld(ssh_session session, ssh_scp scp) {
    int rc;
    const char *helloworld = "Hello, world!\n";
    int length = strlen(helloworld);
    rc = ssh_scp_push_directory(scp, "helloworld", S_IRWXU);
    if (rc != SSH_OK) {
        fprintf(stderr, "Can't create remote directory: %s\n",
                ssh_get_error(session));
        return rc;
    }
    rc = ssh_scp_push_file
            (scp, "helloworld.txt", length, S_IRUSR | S_IWUSR);
    if (rc != SSH_OK) {
        fprintf(stderr, "Can't open remote file: %s\n",
                ssh_get_error(session));
        return rc;
    }
    rc = ssh_scp_write(scp, helloworld, length);
    if (rc != SSH_OK) {
        fprintf(stderr, "Can't write to remote file: %s\n",
                ssh_get_error(session));
        return rc;
    }
    return SSH_OK;
}

int scp_write(ssh_session session) {
    ssh_scp scp;
    int rc;
    scp = ssh_scp_new
            (session, SSH_SCP_WRITE | SSH_SCP_RECURSIVE, ".");
    if (scp == NULL) {
        fprintf(stderr, "Error allocating scp session: %s\n", ssh_get_error(session));
        return SSH_ERROR;
    }
    rc = ssh_scp_init(scp);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error initializing scp session: %s\n",
                ssh_get_error(session));
        ssh_scp_free(scp);
        return rc;
    }

    scp_helloworld(session, scp);

    ssh_scp_close(scp);
    ssh_scp_free(scp);
    return SSH_OK;
}

void error(const char *s)
{
  /* perror() devuelve la cadena S y el error (en cadena de caracteres) que tenga errno */
  perror (s);
  exit(EXIT_FAILURE);
}

void procesoArchivo(char *archivo)
{
  /* Para "procesar", o al menos, hacer algo con el archivo, vamos a decir su tamaño en bytes */
  /* para ello haremos lo que vemos aquí: http://totaki.com/poesiabinaria/2010/04/tamano-de-un-fichero-en-c/ */
  FILE *fich;
  long ftam;

  fich=fopen(archivo, "r");
  if (fich)
    {
      fseek(fich, 0L, SEEK_END);
      ftam=ftell(fich);
      fclose(fich);
      /* Si todo va bien, decimos el tamaño */
      printf ("%30s (%ld bytes)\n", archivo, ftam);
    }
  else
    /* Si ha pasado algo, sólo decimos el nombre */
    printf ("%30s (No info.)\n", archivo);
}

int send_file (const char* dir, const char* filename, ssh_session session) {  
   
    streampos size;
    char * memblock;
    
    string fulldir = "";
    fulldir.append(dir);
    fulldir.append("\\");
    fulldir.append(filename);
    
    
    ifstream myfile (fulldir.c_str(), ios::in | ios::binary | ios::ate);
    if (myfile.is_open())
  {
    size = myfile.tellg();
    memblock = new char [size];
    myfile.seekg (0, ios::beg);
    myfile.read (memblock, size);
    myfile.close();

    cout << "the entire file content is in memory";

    
    
    ssh_scp scp;
    int rc;
    scp = ssh_scp_new
            (session, SSH_SCP_WRITE | SSH_SCP_RECURSIVE, ".");
    if (scp == NULL) {
        fprintf(stderr, "Error allocating scp session: %s\n", ssh_get_error(session));
        return SSH_ERROR;
    }
    rc = ssh_scp_init(scp);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error initializing scp session: %s\n",
                ssh_get_error(session));
        ssh_scp_free(scp);
        return rc;
    }

    //int rc;
    //const char *helloworld = "Hello, world!\n";
    //int length = strlen(helloworld);
    
    rc = ssh_scp_push_directory(scp, "testing", S_IRWXU);
    if (rc != SSH_OK) {
        fprintf(stderr, "Can't create remote directory: %s\n",
                ssh_get_error(session));
        return rc;
    }
    
    rc = ssh_scp_push_file (scp, filename, size, S_IRUSR | S_IWUSR);
    if (rc != SSH_OK) {
        fprintf(stderr, "Can't open remote file: %s\n",
                ssh_get_error(session));
        return rc;
    }
    rc = ssh_scp_write(scp, memblock, size);
    if (rc != SSH_OK) {
        fprintf(stderr, "Can't write to remote file: %s\n",
                ssh_get_error(session));
        return rc;
    }

    ssh_scp_close(scp);
    ssh_scp_free(scp);
   
    
    delete[] memblock;
  }

    
    return SSH_OK;
}

int send_dir_allfiles(const char* directory, ssh_session session) {

    /* Con un puntero a DIR abriremos el directorio */
    DIR *dir;
    /* en *ent habrá información sobre el archivo que se está "sacando" a cada momento */
    struct dirent *ent;

    /* Empezaremos a leer en el directorio actual */
    dir = opendir(directory);

    /* Miramos que no haya error */
    if (dir == NULL)
        error("No puedo abrir el directorio");

    /* Una vez nos aseguramos de que no hay error, ¡vamos a jugar! */
    /* Leyendo uno a uno todos los archivos que hay */
    while ((ent = readdir (dir)) != NULL){
        /* Nos devolverá el directorio actual (.) y el anterior (..), como hace ls */
        if ( (strcmp(ent->d_name, ".")!=0) && (strcmp(ent->d_name, "..")!=0) )
      {
        /* Una vez tenemos el archivo, lo pasamos a una función para procesarlo. */
        //procesoArchivo(ent->d_name);
        send_file(directory, ent->d_name, session);
      }
      }
    closedir (dir);

    return SSH_OK;


    /*ssh_scp scp;
    int rc;
    scp = ssh_scp_new(session, SSH_SCP_WRITE | SSH_SCP_RECURSIVE, ".");
    if (scp == NULL) {
        fprintf(stderr, "Error allocating scp session: %s\n", ssh_get_error(session));
        return SSH_ERROR;
    }
    rc = ssh_scp_init(scp);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error initializing scp session: %s\n",
                ssh_get_error(session));
        ssh_scp_free(scp);
        return rc;
    }

    scp_helloworld(session, scp);

    ssh_scp_close(scp);
    ssh_scp_free(scp);
    return SSH_OK;*/
}

int main(int argc, char** argv) {

    if (existsFile("data.conf"))
        cout << "Data file exist, TODO config data" << endl;
    else
        cout << "Does not exist data config TODO autocreate one with default values" << endl;

    if (existsFile("id_rsa.pub"))
        cout << "RSA file exist TODO security keys" << endl;
    else
        cout << "Does not exist RSA data TODO new security keys" << endl;


    string trash;
    //getline(std::cin, trash);

    ssh_session my_ssh_session;
    int rc;
    char *password;

    // Open session and set options
    my_ssh_session = ssh_new();
    if (my_ssh_session == NULL)
        exit(-1);
    ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, "192.168.1.174");
    ssh_options_set(my_ssh_session, SSH_OPTIONS_USER, "museradmin");

    // Connect to server
    rc = ssh_connect(my_ssh_session);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error connecting to localhost: %s\n", ssh_get_error(my_ssh_session));
        ssh_free(my_ssh_session);
        exit(-1);
    }

    // Verify the server's identity
    // For the source code of verify_knowhost(), check previous example
    if (verify_knownhost(my_ssh_session) < 0) {
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        exit(-1);
    }

    // Authenticate ourselves
    //password = getpass("Password: ");
    rc = authenticate_pubkey(my_ssh_session);
    if (rc != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "Error authenticating with password: %s\n",
                ssh_get_error(my_ssh_session));
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        exit(-1);
    } else {
        cout << "Es valido" << endl;
    }

    /*if(SSH_OK == shell_session(my_ssh_session)){
        cout << "La shell se ha ejecutado correctamente" << endl;
    }*/

    /*if (SSH_OK == scp_write(my_ssh_session)) {
        cout << "La shell se ha ejecutado correctamente" << endl;
    }*/
    
    if (SSH_OK == send_dir_allfiles(".\\dir\\current", my_ssh_session)) {
        cout << "La shell se ha ejecutado correctamente" << endl;
    }

    getline(std::cin, trash);

    return 0;
}

