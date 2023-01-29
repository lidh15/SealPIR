# reference: https://blog.csdn.net/qq_32460819/article/details/108518827
import selectors
import subprocess
import sys
import queue
import socket
from pir_xh import preprocess_id, save_results

ADDRESS = ("127.0.0.1", 5010)
user_queue = queue.Queue()


def send_message(msg):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(ADDRESS)
    s.send(str(msg).encode())
    s.close()


def prepare_queries(quries_file='../../data/A_PIR_ID.csv'):
    with open(quries_file) as f:
        f.readline()
        lines = f.readlines()
    user_queue.put((None, len(lines)))
    for query in lines:
        id1, id2 = preprocess_id(query.strip())
        send_message(id1)
        user_queue.put((query, id2))


def run_client(bin_path='../bin/client_xh',
               log_path='../../results/client.log'):
    results = {}
    p = subprocess.Popen(bin_path,
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         universal_newlines=True)
    
    q_list = []
    p_list = []
    while not user_queue.empty():
        querying, provided = user_queue.get()
        q_list.append(querying)
        p_list.append(str(provided))
    q_list.pop(0)
    # print("client querying: ", p_list)
    logs, error = p.communicate(input=("\n".join(p_list)) + "\n" )
    results_list = [err + '\n' for err in error.split('\n')[:-1]]
    for querying, result in zip(q_list, results_list):
        results[querying] = result

#     logs = []
#     # Read both stdout and stderr simultaneously
#     sel = selectors.DefaultSelector()
#     sel.register(p.stdout, selectors.EVENT_READ)
#     sel.register(p.stderr, selectors.EVENT_READ)
#     querying = None
#     provided = None
#     ok = True
#     while ok:
#         for key, _ in sel.select():
#             line = key.fileobj.readline()
#             if not line:
#                 ok = False
#                 break
#             if key.fileobj is p.stdout:
#                 print(f"STDOUT: {line}", end="")
#                 logs.append(line)
#                 if line.startswith('Xh: Provide '):
#                     querying, provided = user_queue.get()
#                     print(f'STDOUT: writing {provided}\n to stdin', end='')
#                     p.stdin.write(f'{provided}\n')
#                     logs.append(provided)
#             else:
#                 results[querying] = line

    with open(log_path, 'w') as f:
        f.writelines(logs)
    save_results(results)

if __name__ == '__main__':
    prepare_queries()
    run_client()
