#include "pir.hpp"
#include "xh.hpp"
#include <fstream>
#include <iostream>
#include <seal/seal.h>
#include <netinet/in.h>
#include <sys/socket.h>

// void socket_send(int sockfd, const std::string &msg, int send_size, char *socket_buffer, int buffer_size)
// {
//     memset(&socket_buffer, 0, buffer_size);
//     int batch_num = send_size / socket_recv_size;
//     if (send_size % socket_recv_size > 0)
//     {
//         batch_num += 1;
//     }
//     std::cout << "Xh: Transfering size: " << send_size << std::endl;
//     int tmp = htonl(send_size);
//     send(sockfd, &tmp, sizeof(tmp), 0);
//     // ofstream os;
//     // os.open("clientside", ios::out);
//     // os << msg;
//     // os.close();
//     memcpy(socket_buffer, msg.data(), send_size);
//     std::cout << "Xh: Transfering" << std::endl;
//     send(sockfd, socket_buffer, socket_recv_size * batch_num, 0);
// }

// std::string socket_recv(int sockfd, char *socket_buffer, int buffer_size)
// {
//     memset(&socket_buffer, 0, buffer_size);
//     int tmp, recv_len;
//     recv(sockfd, &tmp, sizeof(tmp), 0);
//     recv_len = ntohl(tmp);
//     memset(&socket_buffer, 0, buffer_size);
//     std::cout << "Xh: Receiving" << std::endl;
//     for (uint32_t i = 0; i < recv_len; i += socket_recv_size)
//     {
//         recv(sockfd, socket_buffer + i, socket_recv_size, 0);
//     }
//     std::string msg;
//     msg.assign(socket_buffer, recv_len);
//     return msg;
// }
