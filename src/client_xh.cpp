#include "pir.hpp"
#include "pir_client.hpp"
#include "pir_server.hpp"
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <random>
#include <seal/seal.h>

using namespace std::chrono;
using namespace std;
using namespace seal;

int main(int argc, char *argv[]) {
  // Hyper parameters
  uint8_t shift_bit_num = 20;
  int port = 5011;
  int socket_size = 1024 * 1024;
  
  struct sockaddr_in servaddr;
  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(port);
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  inet_pton(AF_INET, "127.0.0.1", &servaddr.sin_addr);
  connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr));
  char sendline[socket_size];

  uint64_t number_of_items = 1 << shift_bit_num;
  uint64_t size_per_item = 4; // in bytes
  uint32_t N = 4096;

  // Recommended values: (logt, d) = (20, 2).
  uint32_t logt = 20;
  uint32_t d = 2;
  bool use_symmetric = true; // use symmetric encryption instead of public key
                             // (recommended for smaller query)
  bool use_batching = true;  // pack as many elements as possible into a BFV
                             // plaintext (recommended)
  bool use_recursive_mod_switching = true;

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

  // Initialize PIR client....
  PIRClient client(enc_params, pir_params);
  cout << "Xh: Generating galois keys for client" << endl;

  GaloisKeys galois_keys = client.generate_galois_keys();

  // Transfer keys
  memset(&sendline, 0, sizeof(sendline));
  sendline = serialize_galoiskeys(galois_keys);
  send(sockfd, sendline, strlen(sendline), 0);

  // Choose an index of an element in the DB
  uint64_t ele_index;
  cin >> ele_index;
  uint64_t index = client.get_fv_index(ele_index);   // index of FV plaintext
  uint64_t offset = client.get_fv_offset(ele_index); // offset in FV plaintext
  cout << "Xh: FV index = " << index << ", FV offset = " << offset << endl;

  // Measure serialized query generation (useful for sending over the network)
  stringstream client_stream;
  auto time_s_query_s = high_resolution_clock::now();
  int query_size = client.generate_serialized_query(index, client_stream);
  auto time_s_query_e = high_resolution_clock::now();
  auto time_s_query_us =
      duration_cast<microseconds>(time_s_query_e - time_s_query_s).count();
  cout << "Xh: serialized query generated" << endl;

  // Transfer queries
  memset(&sendline, 0, sizeof(sendline));
  sendline = client_stream.str();
  send(sockfd, sendline, strlen(sendline), 0);

  // Transfer replies
  memset(&sendline, 0, sizeof(sendline));
  int recv_len = recv(sockfd, sendline, socket_size, 0);
  PirReply reply;
  client.deserialize_reply(reply, client_stream);

  // Measure response extraction
  auto time_decode_s = chrono::high_resolution_clock::now();
  vector<uint8_t> elems = client.decode_reply(reply, offset);
  auto time_decode_e = chrono::high_resolution_clock::now();
  auto time_decode_us =
      duration_cast<microseconds>(time_decode_e - time_decode_s).count();
  cout << "Xh: reply decoded" << endl;

  assert(elems.size() == size_per_item);

  // Output results
  cout << "Xh: PIRClient serialized query generation time: "
       << time_s_query_us / 1000 << " ms" << endl;
  cout << "Xh: PIRClient answer decode time: " << time_decode_us / 1000
       << " ms" << endl;
  cout << "Xh: Query size: " << query_size << " bytes" << endl;
  cout << "Xh: Reply num ciphertexts: " << reply.size() << endl;

  return 0;
}
