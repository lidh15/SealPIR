#include "pir.hpp"
#include "pir_client.hpp"
#include "pir_server.hpp"
#include "xh.hpp"
// #include <stdlib.h>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <random>
#include <unistd.h>
#include <seal/seal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

using namespace std::chrono;
using namespace std;
using namespace seal;

int main(int argc, char *argv[])
{
  char socket_buffer[socket_size];
  uint32_t tmp, recv_len, send_size, batch_num;
  struct sockaddr_in servaddr;
  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(port);

  int sockfd0 = socket(AF_INET, SOCK_STREAM, 0);
  servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  bind(sockfd0, (struct sockaddr *)&servaddr, sizeof(servaddr));
  listen(sockfd0, 10);
  int sockfd1 = accept(sockfd0, (struct sockaddr *)NULL, NULL);
  int sockfd2 = accept(sockfd0, (struct sockaddr *)NULL, NULL);

  EncryptionParameters enc_params(scheme_type::bfv);
  PirParams pir_params;

  // Generates all parameters
  cout << "Xh: Generating SEAL parameters" << endl;
  gen_encryption_params(N, logt, enc_params);

  cout << "Xh: Verifying SEAL parameters" << endl;
  verify_encryption_params(enc_params);
  cout << "Xh: SEAL parameters are good" << endl;

  cout << "Xh: Generating PIR parameters" << endl;
  gen_pir_params(number_of_items, size_per_item, d, enc_params, pir_params,
                 use_symmetric, use_batching, use_recursive_mod_switching);

  print_seal_params(enc_params);
  print_pir_params(pir_params);

  // Initialize PIR Server
  cout << "Xh: Initializing server" << endl;
  PIRServer server(enc_params, pir_params);

  // Transfer keys
  recv(sockfd1, &tmp, sizeof(tmp), 0);
  recv_len = ntohl(tmp);
  memset(&socket_buffer, 0, sizeof(socket_buffer));
  cout << "Xh: Receiving galois keys with expected size " << recv_len << endl;
  for (uint32_t i = 0; i < recv_len; i += socket_recv_size)
  {
    recv(sockfd1, socket_buffer + i, socket_recv_size, 0);
  }
  string galois_keys_string;
  galois_keys_string.assign(socket_buffer, recv_len);

  GaloisKeys galois_keys = *deserialize_galoiskeys(galois_keys_string, make_shared<SEALContext>(enc_params, true));
  cout << "Xh: galois keys deserialized" << endl;

  // Server maps the galois key to client 0. We only have 1 client,
  // which is why we associate it with 0. If there are multiple PIR
  // clients, you should have each client generate a galois key,
  // and assign each client an index or id, then call the procedure below.
  server.set_galois_key(0, galois_keys);

  uint64_t hit_point_num, hit_index, val;
  recv(sockfd1, &tmp, sizeof(tmp), 0);
  int query_num = ntohl(tmp);
  for (int i = 0; i < query_num; i++)
  {
    cout << "Xh: Creating the database with sliced data (this may take some "
            "time) ..."
         << endl;

    // Create test database
    auto db(make_unique<uint8_t[]>(number_of_items * size_per_item));
    int offset = 0;
    for (uint64_t i = 0; i < number_of_items; i++)
    {
      offset += size_per_item;
      for (uint8_t j = 0; j < size_per_item; j++)
      {
        db.get()[offset + j] = 255;
      }
    }

    cin >> hit_point_num;
    // cout << "Xh: Hit point number: " << hit_point_num << endl;
    for (uint64_t i = 0; i < hit_point_num; i++)
    {
      cin >> hit_index;
      // cout << "Xh: Hit point index: " << hit_index << endl;
      for (uint8_t j = 0; j < size_per_item; j++)
      {
        cin >> val;
        db.get()[hit_index * size_per_item + j] = val;
        // cout << "Xh: Hit point value at " << j << ": " << (int)db.get()[hit_index * size_per_item + j] << endl;
      }
    }

    // Measure database setup
    auto time_pre_s = high_resolution_clock::now();
    server.set_database(move(db), number_of_items, size_per_item);
    server.preprocess_database();
    auto time_pre_e = high_resolution_clock::now();
    auto time_pre_us =
        duration_cast<microseconds>(time_pre_e - time_pre_s).count();
    cout << "Xh: database pre processed " << endl;

    // Transfer queries
    recv(sockfd1, &tmp, sizeof(tmp), 0);
    recv_len = ntohl(tmp);
    memset(&socket_buffer, 0, sizeof(socket_buffer));
    cout << "Xh: receiving queries with expected size " << recv_len << endl;
    for (uint32_t i = 0; i < recv_len; i += socket_recv_size)
    {
      recv(sockfd1, socket_buffer + i, socket_recv_size, 0);
    }
    string query_string;
    query_string.assign(socket_buffer, recv_len);

    // ofstream os;
    // os.open("serverside", ios::out);
    // os << query_string;
    // os.close();
    stringstream server_stream(query_string);

    // Measure query deserialization (useful for receiving over the network)
    auto time_deserial_s = high_resolution_clock::now();
    PirQuery query2 = server.deserialize_query(server_stream);
    auto time_deserial_e = high_resolution_clock::now();
    auto time_deserial_us =
        duration_cast<microseconds>(time_deserial_e - time_deserial_s).count();
    cout << "Xh: query deserialized" << endl;

    // Measure query processing (including expansion)
    auto time_server_s = high_resolution_clock::now();
    // Answer PIR query from client 0. If there are multiple clients,
    // enter the id of the client (to use the associated galois key).
    PirReply reply = server.generate_reply(query2, 0);
    auto time_server_e = high_resolution_clock::now();
    auto time_server_us =
        duration_cast<microseconds>(time_server_e - time_server_s).count();
    cout << "Xh: reply generated" << endl;

    server_stream.clear();
    // Serialize reply (useful for sending over the network)
    int reply_size = server.serialize_reply(reply, server_stream);

    // Transfer replies
    send_size = reply_size;
    tmp = htonl(send_size);
    batch_num = send_size / socket_recv_size;
    if (send_size % socket_recv_size > 0)
    {
      batch_num += 1;
    }

    cout << "Xh: Transfering reply size: " << send_size << endl;
    send(sockfd2, &tmp, sizeof(tmp), 0);
    memset(&socket_buffer, 0, sizeof(socket_buffer));
    memcpy(socket_buffer, server_stream.str().data(), reply_size);
    cout << "Xh: Transfering reply" << endl;
    send(sockfd2, socket_buffer, socket_recv_size * batch_num, 0);

    // Output results
    cout << "Xh: PIRServer pre-processing time: " << time_pre_us / 1000 << " ms"
         << endl;
    cout << "Xh: PIRServer query deserialization time: " << time_deserial_us
         << " us" << endl;
    cout << "Xh: PIRServer reply generation time: " << time_server_us / 1000
         << " ms" << endl;
    cout << "Xh: Reply num ciphertexts: " << reply.size() << endl;
    cout << "Xh: Reply size: " << reply_size << " bytes" << endl;
  }
  close(sockfd1);
  close(sockfd2);
  close(sockfd0);
  return 0;
}
