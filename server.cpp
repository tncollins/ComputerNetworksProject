#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <map>
#include <unordered_map>
#include <vector>
#include <string>
struct header
{
    char magic1;
    char magic2;
    char opcode;
    char payload_len;
    uint32_t token;
    uint32_t msg_id;
};
const int h_size = sizeof(struct header);
#define MAGIC_1 'T'
#define MAGIC_2 'C'
// These are the constants indicating the states.
// CAUTION: These states have nothing to do with the states on the client.
#define STATE_ONLINE 1
#define STATE_OFFLINE 0
#define STATE_MSG_FORWARD 2
// Now you can define other states in a similar fashion.
// These are the events
// CAUTION: These events have nothing to do with the states on the client.
#define EVENT_NET_LOGIN 80
#define EVENT_NET_POST 81
#define EVENT_NET_SUBSCRIBE 82
#define EVENT_NET_UNSUBSCRIBE 83
#define EVENT_NET_LOGOUT 84
#define EVENT_NET_RETRIEVE 85
#define EVENT_NET_RESET 86
// Now you can define other events from the network.......
#define EVENT_NET_INVALID 255

// These are the constants indicating the opcodes.
#define OPCODE_RESET 0x00
#define OPCODE_MUST_LOGIN_FIRST_ERROR 0xF0
#define OPCODE_LOGIN 0x10
#define OPCODE_SUCCESSFUL_LOGIN_ACK 0x80
#define OPCODE_FAILED_LOGIN_ACK 0x81
#define OPCODE_SUBSCRIBE 0x20
#define OPCODE_SUCCESSFUL_SUBSCRIBE_ACK 0x90
#define OPCODE_FAILED_SUBSCRIBE_ACK 0x91
#define OPCODE_UNSUBSCRIBE 0x21
#define OPCODE_SUCCESSFUL_UNSUBSCRIBE_ACK 0xA0
#define OPCODE_FAILED_UNSUBSCRIBE_ACK 0xA1
#define OPCODE_POST 0x30
#define OPCODE_POST_ACK 0xB0
#define OPCODE_FORWARD 0xB1
#define OPCODE_FORWARD_ACK 0x31
#define OPCODE_RETRIEVE 0x40
#define OPCODE_RETRIEVE_ACK 0xC0
#define OPCODE_END_OF_RETRIEVE_ACK 0xC1
#define OPCODE_LOGOUT 0x1F
#define OPCODE_LOGOUT_ACK 0x8F

// This is a data structure that holds important information on a session.
struct session
{
    char client_id[32];
     // Assume the client ID is less than 32 characters.
        struct sockaddr_in client_addr;
     // IP address and port of the client
        // for receiving messages from the
        // server.
        time_t last_time; // The last time when the server receives a message
                          // from this client.
        uint32_t token; // The token of this session.
        int state;     // The state of this session, 0 is "OFFLINE", etc.
        // TODO: You may need to add more information such as the subscription
        // list, password, etc.
        char client_password[32];
        std::vector<std::string>subscribers;
        std::vector<std::string> subscribedto;
        std::vector<std::string> subsPosts;
        int numSubs;
};
// TODO: You may need to add more structures to hold global information
// such as all registered clients, the list of all posted messages, etc.
// Initially all sessions are in the OFFLINE state.
std::unordered_map<char*,char*> clients;
std::vector<char*>allMessages;

int extract_token_from_the_received_binary_msg(struct header* recv)
{
   // printf("Getting the token!\n");
    return recv->token; 
}

struct session* find_the_session_by_token(int token,struct session list[16])
{
    //printf("finding by session!\n");
    struct session* ptr = NULL;
    if(token != 0)
    {
        for(int i = 0; i< 3; i++)
        {
            if(list[i].token == token)

            {
                ptr = &list[i];
                return ptr;
            }
        }
    }else{
       return ptr;
    }

}

int parse_the_event_from_the_datagram(struct header* recv)
{
    //printf("getting event\n");
    if(recv->opcode == OPCODE_LOGIN)
    {
        return EVENT_NET_LOGIN;
    }else if(recv->opcode == OPCODE_POST)
    {
        return EVENT_NET_POST;
    }else if(recv->opcode == OPCODE_SUBSCRIBE)
    {
        return EVENT_NET_SUBSCRIBE;
    }else if(recv->opcode == OPCODE_UNSUBSCRIBE)
    {
        return EVENT_NET_UNSUBSCRIBE;
    }else if(recv->opcode == OPCODE_RETRIEVE)
    {
        return EVENT_NET_RETRIEVE;
    }
    else if(recv->opcode == OPCODE_RESET)
    {
        return EVENT_NET_RESET;
    }else if(recv->opcode == OPCODE_LOGOUT){
        return EVENT_NET_LOGOUT;    
    }
        else{
        return EVENT_NET_INVALID;
    }
}

int check_id_password(char* id, char* pass)
{
   // printf("validating user!\n");
    if(clients[id] == pass)
    {
        return 1;
    }else{
        return 0;
    }

}

uint32_t generate_a_random_token()
{
    return (uint32_t)rand();
}

struct session* find_this_client_in_the_session_list(char* user,std::map<int,struct session*>list)
{
    //printf("Getting the client!\n");
    std::map<int,struct session*>::iterator itr;
        for(itr = list.begin();itr!=list.end();++itr)
        {
            if(strncmp(user,itr->second->client_id,strlen(itr->second->client_id)) == 0)
            {
                return itr->second;
            }
        }
}
struct session* find_this_client_in_the_session_array(char* id,struct session s[16])
{
  //  printf("finding client\n");
    for(int i = 0;i<3;i++)
    {
        if(strncmp(id,s[i].client_id,strlen(id)) == 0)
        {
            //printf("found you!\n");
            struct session* ptr = &s[i];
            return ptr;
        }
    }

}

int check_id_password(char *id,char* pass,struct session s[16])
{
    for(int i = 0; i<3;i++)
    {
        if(strncmp(id,s[i].client_id,strlen(id)) == 0)
        {
            if(strncmp(pass,s[i].client_password,strlen(pass)) == 0)
            {
                return 1;
            }
        }
    }
    return 0;

}

bool isSubbedTo(std::vector<std::string>list,std::string name)
{
    for(int i =0; i< list.size(); i++)
    {
        if(list[i] == name)
        {
            return true;
        }
    }
    return false;
}

int main()
{
    //printf("setting up a client for testing!\n");
    //clients["taylor"] = "1234";
    int ret;
    int sockfd;
    struct sockaddr_in serv_addr, cli_addr;
    char send_buffer[1024];
    char recv_buffer[1024];
    int recv_len;
    socklen_t len;
    int messageCount = 0;
    allMessages.push_back("ignore");
    // You may need to use a std::map to hold all the sessions to find a
    // session given a token. I just use an array just for demonstration.
    // Assume we are dealing with at most 16 clients, and this array of
    // the session structure is essentially our user database.
    struct session session_array[16];
    std::map<int,struct session*> sessionList;
    // Now you need to load all users' information and fill this array.
    //printf("creating a client\n");
    struct session client1;
    memcpy(client1.client_id,"taylor",6);
    memcpy(client1.client_password,"1234",4);
    client1.state = STATE_OFFLINE;
    client1.token = 0;
    client1.subscribers.resize(16);
    client1.subscribedto.resize(16);
    session_array[0] = client1;

    struct session client2;
    memcpy(client2.client_id,"client2",7);
    memcpy(client2.client_password,"4567",4);
    client2.state = STATE_OFFLINE;
    client2.token = 0;
    client2.subscribers.resize(16);
    client2.subscribedto.resize(16);
    session_array[1] = client2;

    struct session client3;
    memcpy(client3.client_id,"client3",7);
    memcpy(client3.client_password,"8910",4);
    client3.state = STATE_OFFLINE;
    client3.token = 0;
    client3.subscribers.resize(16);
    client3.subscribedto.resize(16);
    session_array[2] = client3;
    int numClients = 3; //random token to initially load in the clients
   // printf("loading clients!!!!\n");
    /* for(auto c:clients)
    {
        struct session* newSession = (struct session*)malloc(sizeof(struct session));
        memcpy(newSession->client_id,c.first,strlen(c.first));
        memcpy(newSession->client_password,c.second,strlen(c.second));
        newSession->state = 0;
        newSession->token = randtoken;
        sessionList.insert(std::pair<int,struct session*>(randtoken,newSession));
        randtoken++;
    } */
    // Optionally, you can just hardcode each user.
    // This current_session is a variable temporarily hold the session upon
    // an event.
    struct session *current_session = (struct session*)malloc(sizeof(struct session));
    int token;
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        printf("socket() error: %s.\n", strerror(errno));
        return -1;
    }
    // The servaddr is the address and port number that the server will
    // keep receiving from.
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(32000);
    
    bind(sockfd,
            (struct sockaddr *)&serv_addr,
            sizeof(serv_addr));
    // Same as that in the client code.
   // printf("Creating headers!\n");
    struct header *ph_send = (struct header *)send_buffer;
    struct header *ph_recv = (struct header *)recv_buffer;
    while (1)
    {
        // Note that the program will still block on recvfrom()
        // You may call select() only on this socket file descriptor with
        // a timeout, or set a timeout using the socket options.
        len = sizeof(cli_addr);
        memset(recv_buffer,0,sizeof(recv_buffer));
        memset(send_buffer,0,sizeof(send_buffer));
        recv_len = recvfrom(sockfd,               // socket file descriptor
                                recv_buffer, // receive buffer
                                sizeof(recv_buffer),           // number of bytes to be received
                                0,
                                (struct sockaddr *)&cli_addr,  // client address
                                & len);
        // length of client address structure
        if (recv_len <= 0)
        {
            printf("recvfrom() error: %s.\n", strerror(errno));
            return -1;
        }
        // Now we know there is an event from the network
        // Figure out which event and process it according to the
        // current state of the session referred.
       // printf("\nGetting Data!\n");
        int token = extract_token_from_the_received_binary_msg(ph_recv);
        // This is the current session we are working with.
        struct session *cs = find_the_session_by_token(token,session_array);
        //struct session *cs = NULL;
        int event = parse_the_event_from_the_datagram(ph_recv);
         // Record the last time that this session is active.
         //printf("setting up the current session!\n");
        current_session->last_time = time(NULL);
        if(cs!=NULL)
        {
            cs->last_time = current_session->last_time;

        }
        
        if (event == EVENT_NET_LOGIN)
        {
             // For a login message, the current_session should be NULL and
             // the token is 0. For other messages, they should be valid.
           // printf("Logging in!\n");
            char *id_password = recv_buffer + h_size;
            char *delimiter = strchr(id_password, '&');
            char *password = delimiter + 1;
            *delimiter = 0;
             // Add a null terminator
            // Note that this null terminator can break the user ID
            // and the password without allocating other buffers.
            char *user_id = id_password;
            delimiter = strchr(password, '\n');
            *delimiter = 0;
             // Add a null terminator
            // Note that since we did not process it on the client side,
            // and since it is always typed by a user, there must be a
            // trailing new line. We just write a null terminator on this
            // place to terminate the password string.
            // The server need to reply a msg anyway, and this reply msg
            // contains only the header
            ph_send->magic1 = MAGIC_1;
            ph_send->magic2 = MAGIC_2;
            ph_send->payload_len = 0;
            ph_send->msg_id = 0;
            //int login_success = check_id_password(user_id, password);
            int login_success = check_id_password(user_id, password,session_array);

            if (login_success > 0)
            {
                // This means the login is successful.
                ph_send->opcode = OPCODE_SUCCESSFUL_LOGIN_ACK;
                ph_send->token = generate_a_random_token();
                //cs = find_this_client_in_the_session_list(user_id,sessionList);
                cs = find_this_client_in_the_session_array(user_id,session_array);
                cs->state = STATE_ONLINE;
                cs->token = ph_send->token;
                cs->last_time = time(NULL);
                cs->client_addr = cli_addr;
               // printf("congrats on loggin in!\n");
            }
            else
            {
                ph_send->opcode = OPCODE_FAILED_LOGIN_ACK;
                ph_send->token = 0;
            }
            sendto(sockfd, send_buffer, h_size, 0, (struct sockaddr *) & cli_addr, sizeof(cli_addr));
           // printf("Just sent your ack. hope you got in\n");
        }
        else if (event == EVENT_NET_POST)
        {
            
          //  printf("you're posting!\n");
          if(cs!= NULL)
          {
            if(cs->state == STATE_ONLINE)
            {
               // printf("And youre online\n");
                messageCount += 1;
                
                char *text = recv_buffer + h_size;
                char *payload = send_buffer + h_size;
                // This formatting the "<client_a>some_text" in the payload
                // of the forward msg, and hence, the client does not need
                // to format it, i.e., the client can just print it out.
                snprintf(payload, sizeof(send_buffer) - h_size, "<%s>%s",
                            cs->client_id, text);
                int m = strlen(payload) - 1;
                for(int i = 0;i<cs->numSubs;i++)
                {
                    // "target" is the session structure of the target client.
                    struct session* target = find_this_client_in_the_session_array((char *)cs->subscribers[i].c_str(),session_array);
                    std::string message = payload;
                    target->subsPosts.push_back(message);
                    if(target->state == STATE_ONLINE)
                    {
                        target->state = STATE_MSG_FORWARD;
                        ph_send->magic1 = MAGIC_1;
                        ph_send->magic2 = MAGIC_2;
                        ph_send->opcode = OPCODE_FORWARD;
                        ph_send->payload_len = m;
                        ph_send->msg_id = messageCount;
                     //   printf("Size: %d\n",m);
                        // Note that I didn't use msg_id here.
                     //   printf("send_buffer: %s\n",(send_buffer+h_size));
                        sendto(sockfd, send_buffer, h_size+m, 0, (struct sockaddr *) & target->client_addr,
                            sizeof(target->client_addr));
                        socklen_t size = sizeof(target->client_addr);
                        char ack[1024];
                        struct header* ph_ack = (struct header*)ack;
                        recv_len = recvfrom(sockfd,               // socket file descriptor
                                    ack, // receive buffer
                                    sizeof(ack),           // number of bytes to be received
                                    0,
                                    (struct sockaddr *)&target->client_addr,  // client address
                                    &size);

                        target->state = STATE_ONLINE;
                    }
                    
                }
                // TODO: send back the post ack to this publisher.
                ph_send->magic1 = MAGIC_1;
                ph_send->magic2 = MAGIC_2;
                ph_send->opcode = OPCODE_POST_ACK;
                ph_send->payload_len = 0;
                ph_send->msg_id = 0;
                sendto(sockfd, send_buffer, h_size, 0, (struct sockaddr *) & cs->client_addr,
                        sizeof(cs->client_addr));
                //printf("sending the ack back. congrats on posting\n");
                // TODO: put the posted text line into a global list.
                allMessages.push_back((recv_buffer+h_size));
            }else{
                ph_send->magic1 = MAGIC_1;
                ph_send->magic2 = MAGIC_2;
                ph_send->opcode = OPCODE_MUST_LOGIN_FIRST_ERROR;
                ph_send->payload_len = 0;
                ph_send->msg_id = 0;
                sendto(sockfd, send_buffer, h_size, 0, (struct sockaddr *) & cli_addr,
                        sizeof(cli_addr));
                

            }
          }else{
                ph_send->magic1 = MAGIC_1;
                ph_send->magic2 = MAGIC_2;
                ph_send->opcode = OPCODE_MUST_LOGIN_FIRST_ERROR;
                ph_send->payload_len = 0;
                ph_send->msg_id = 0;
                sendto(sockfd, send_buffer, h_size, 0, (struct sockaddr *) & cli_addr,
                        sizeof(cli_addr));
          }           
            
        }
        else if (event == EVENT_NET_SUBSCRIBE)
        {
            
            if(cs->state == STATE_ONLINE)
            {
                char c[32];
                memcpy(c,recv_buffer+h_size,strlen(recv_buffer+h_size)-1);
               // printf("Who I want to sub to %s\n",c);
                ph_send->opcode = OPCODE_FAILED_SUBSCRIBE_ACK;
                for(int i = 0; i< numClients;i++)
                {
                    //printf("client %d: %s\n",i,session_array[i].client_id);
                    if(strncmp(c,session_array[i].client_id,strlen(session_array[i].client_id)) == 0)
                    {
                       // printf("Found!\n");
                        //memset(cs->subscribedto[i],0,sizeof(cs->subscribedto[i]));
                       // printf("copying!\n");
                        //memcpy(cs->subscribedto[i], c,strlen(c));
                        cs->subscribedto[i] = c;
                        //printf("Adding you to the list!\n");
                        session_array[i].subscribers[i] = cs->client_id;
                        session_array[i].numSubs++;
                        ph_send->opcode = OPCODE_SUCCESSFUL_SUBSCRIBE_ACK;
                        break;
                    }

                }
                
                ph_send->magic1 = MAGIC_1;
                ph_send->magic2 = MAGIC_2;
                ph_send->payload_len = 0;
                ph_send->msg_id = 0;
                sendto(sockfd, send_buffer, h_size, 0, (struct sockaddr *) & cs->client_addr,
                        sizeof(cs->client_addr));
            }else{
                ph_send->magic1 = MAGIC_1;
                ph_send->magic2 = MAGIC_2;
                ph_send->payload_len = 0;
                ph_send->msg_id = 0;
                ph_send->opcode = OPCODE_MUST_LOGIN_FIRST_ERROR;
                sendto(sockfd, send_buffer, h_size, 0, (struct sockaddr *) &cli_addr,
                        sizeof(cli_addr));
            }
            
            // TODO: process other events
        }else if(event == EVENT_NET_UNSUBSCRIBE)
        {
            if(cs->state == STATE_ONLINE)
            {
                char c[32];
                memcpy(c,recv_buffer+h_size,strlen(recv_buffer+h_size)-1);
               // printf("Who I want to UNsub to %s\n",c);
                int i = 0;
                ph_send->opcode = OPCODE_FAILED_UNSUBSCRIBE_ACK;
                for(auto it = cs->subscribedto.begin();it!=cs->subscribedto.end();++it)
                {
                    //printf("client %d: %s\n",i,session_array[i].client_id);
                    if(strncmp(c,(*it).c_str(),(*it).length()) == 0)
                    {
                       // printf("Found!\n");
                        //memset(cs->subscribedto[i],0,sizeof(cs->subscribedto[i]));
                        //printf("copying!\n");
                        //memcpy(cs->subscribedto[i], c,strlen(c));
                        cs->subscribedto.erase(it);
                       // printf("Adding you to the list!\n");
                        for(auto rt = session_array[i].subscribers.begin();rt!=session_array[i].subscribers.end();++rt)
                        {
                            if((*it) == (*rt))
                            {
                                session_array[i].subscribers.erase(rt);
                                break;
                            }
                        }
                        session_array[i].numSubs--;
                        ph_send->opcode = OPCODE_SUCCESSFUL_UNSUBSCRIBE_ACK;
                        break;
                    }
                    i++;

                }
                
                ph_send->magic1 = MAGIC_1;
                ph_send->magic2 = MAGIC_2;
                ph_send->payload_len = 0;
                ph_send->msg_id = 0;
                sendto(sockfd, send_buffer, h_size, 0, (struct sockaddr *) & cs->client_addr,
                        sizeof(cs->client_addr));
            }else{
                ph_send->magic1 = MAGIC_1;
                ph_send->magic2 = MAGIC_2;
                ph_send->payload_len = 0;
                ph_send->msg_id = 0;
                ph_send->opcode = OPCODE_MUST_LOGIN_FIRST_ERROR;
                sendto(sockfd, send_buffer, h_size, 0, (struct sockaddr *) & cli_addr,
                        sizeof(cli_addr));
            }
        }else if(event == EVENT_NET_RETRIEVE)
        {
            if(cs->state == STATE_ONLINE)
            {
                int numMessages = ph_recv->payload_len;
                ph_send->magic1 = MAGIC_1;
                ph_send->magic2 = MAGIC_2;
                
                ph_send->opcode = OPCODE_RETRIEVE_ACK;
                
                int index = 0;
                for(int i =0;i< numMessages;i++)
                {
                    
                    memcpy(send_buffer+h_size,cs->subsPosts[i].c_str(),cs->subsPosts[i].size());
                    ph_send->payload_len = i+1;

                    sendto(sockfd, send_buffer, sizeof(send_buffer), 0, (struct sockaddr *) & cs->client_addr,
                                            sizeof(cs->client_addr));
                }
                ph_send->opcode = OPCODE_END_OF_RETRIEVE_ACK;

            }else{
                ph_send->magic1 = MAGIC_1;
                ph_send->magic2 = MAGIC_2;
                ph_send->payload_len = 0;
                ph_send->msg_id = 0;
                ph_send->opcode = OPCODE_MUST_LOGIN_FIRST_ERROR;
                sendto(sockfd, send_buffer, h_size, 0, (struct sockaddr *) & cli_addr,
                        sizeof(cli_addr));
            }
        }else if(event == EVENT_NET_LOGOUT)
        {
            if(cs->state == STATE_ONLINE)
            {
                cs->state = STATE_OFFLINE;
                cs->token = 0;
                ph_send->magic1 = MAGIC_1;
                ph_send->magic2 = MAGIC_2;
                ph_send->payload_len = 0;
                ph_send->token = cs->token;
                ph_send->msg_id = 0;
                ph_send->opcode = OPCODE_LOGOUT_ACK;
                sendto(sockfd, send_buffer, h_size, 0, (struct sockaddr *) & cs->client_addr,
                        sizeof(cs->client_addr));
            }else{
                ph_send->magic1 = MAGIC_1;
                ph_send->magic2 = MAGIC_2;
                ph_send->payload_len = 0;
                ph_send->msg_id = 0;
                ph_send->opcode = OPCODE_MUST_LOGIN_FIRST_ERROR;
                sendto(sockfd, send_buffer, h_size, 0, (struct sockaddr *) &cli_addr,
                        sizeof(cli_addr));
            }
            
        }else if(event == EVENT_NET_RESET)
        {
            printf("Connection reset!\n");
            cs->state = STATE_OFFLINE;
        }else{
            cs->state = STATE_OFFLINE;
            ph_send->magic1 = MAGIC_1;
            ph_send->magic2 = MAGIC_2;
            ph_send->opcode = OPCODE_RESET;
            ph_send->msg_id = 0;
            ph_send->token = 0;
            ph_send->payload_len = 0;
            sendto(sockfd,send_buffer, h_size, 0, (struct sockaddr *) & cs->client_addr,
                        sizeof(cs->client_addr));
        }
        time_t current_time = time(NULL);
        // Now you may check the time of clients, i.e., scan all sessions.
        // For each session, if the current time has passed 5 minutes plus
        // the last time of the session, the session expires.
        for(int i =0;i<numClients;i++)
        {
            if(session_array[i].state == STATE_ONLINE)
            {
                if(current_time - session_array[i].last_time > 0)
                {
                    cs->state = STATE_OFFLINE;
                    ph_send->magic1 = MAGIC_1;
                    ph_send->magic2 = MAGIC_2;
                    ph_send->opcode = OPCODE_RESET;
                    ph_send->msg_id = 0;
                    ph_send->token = cs->token;
                    ph_send->payload_len = 0;
                    sendto(sockfd,send_buffer, h_size, 0, (struct sockaddr *) & cs->client_addr,
                                sizeof(cs->client_addr));
                }

            }
            
        }

    }
     // This is the end of the while loop
        return 0;
}
 // This is the end of main()
