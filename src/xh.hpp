#pragma once

// Hyper parameters
const uint8_t shift_bit_num = 20;
const uint64_t number_of_items = 1 << shift_bit_num;
const uint64_t size_per_item = 4; // in bytes
const uint32_t N = 4096;
const int port = 5011;
const int socket_size = 4 * 1024 * 1024;
const int socket_recv_size = 128;

// Recommended values: (logt, d) = (20, 2).
const uint32_t logt = 20;
const uint32_t d = 2;
const bool use_symmetric = true; // use symmetric encryption instead of public key
                                 // (recommended for smaller query)
const bool use_batching = true;  // pack as many elements as possible into a BFV
                                 // plaintext (recommended)
const bool use_recursive_mod_switching = true;

// Socket related
// void socket_send(int sockfd, const std::string &msg, int send_size, char *socket_buffer, int buffer_size);
// std::string socket_recv(int sockfd, char *socket_buffer, int buffer_size);
