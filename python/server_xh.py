# reference: https://blog.csdn.net/qq_32460819/article/details/108518827
import selectors
import subprocess
import sys
import time
import queue
import socket
import threading
from collections import defaultdict
from pir_xh import preprocess_id, database_serialize

ADDRESS = ('127.0.0.1', 5010)
DATA = defaultdict(list)
g_socket_server = None  # 负责监听的socket
g_conn_pool = []  # 连接池
client_cnt = 0
user_queue = queue.Queue()


def init():
    """
    初始化服务端
    """
    global g_socket_server
    g_socket_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    g_socket_server.bind(ADDRESS)
    g_socket_server.listen(5)  # 最大等待数（有很多人理解为最大连接数，其实是错误的）
    # print("服务端已启动，等待客户端连接...")


def accept_client():
    """
    接收新连接
    """
    global client_cnt
    while True:
        client, _ = g_socket_server.accept()  # 阻塞，等待客户端连接
        # 加入连接池
        g_conn_pool.append(client)
        client_cnt += 1
        # # 给每个客户端创建一个独立的线程进行管理
        # thread = threading.Thread(target=message_handle, args=(client, ))
        # # 设置成守护线程
        # thread.setDaemon(True)
        # thread.start()
        message_handle(client)


def message_handle(client):
    """
    消息处理
    """
    # global user_queue
    data = client.recv(1024)  # 接收buffer的大小
    data = DATA.get(data.decode(), [])
    data_string = "\n".join(data)
    user_queue.put(f'{len(data)}\n{data_string}')
    try:
        client.close()  # 删除连接
    except Exception as e:
        print(e)
    g_conn_pool.remove(client)
    # print("有一个客户端下线了。")


def prepare_input(data_file='../../data/B_PIR_DATA.csv'):
    with open(data_file) as f:
        f.readline()
        data = f.readlines()
    # try do this in multi threads to accelerate
    for datum in data:
        index, values = datum.split(',', 1)
        id1, id2 = preprocess_id(index)
        value_string = database_serialize(values)
        DATA[str(id1)].append(f'{id2}\n{value_string}')


def run_server(bin_path='../bin/server_xh',
               log_path='../../results/server.log'):
    p = subprocess.Popen(bin_path,
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         universal_newlines=True)
    
    while not client_cnt:
        print("waiting for client ...")
        time.sleep(10)
    p_list = []
    while not user_queue.empty():
        provided = user_queue.get()
        p_list.append(provided)
    # print("server preparing: ", p_list)
    logs, _ = p.communicate(input="".join(p_list))

#     logs = []
#     # Read both stdout and stderr simultaneously
#     sel = selectors.DefaultSelector()
#     sel.register(p.stdout, selectors.EVENT_READ)
#     sel.register(p.stderr, selectors.EVENT_READ)
#     ok = True
#     while ok:
#         for key, _ in sel.select():
#             line = key.fileobj.readline()
#             if not line:
#                 ok = False
#                 break
#             logs.append(line)
#             if key.fileobj is p.stdout:
#                 print(f"STDOUT: {line}", end="")
#                 if line.startswith(
#                         'Xh: Creating the database with sliced data (this may take some time) ...'
#                 ):
#                     provided = user_queue.get()
#                     print(f'STDOUT: writing {provided} to stdin', end='')
#                     p.stdin.write(provided)
#             else:
#                 print(f"STDERR: {line}", end="", file=sys.stderr)

    with open(log_path, 'w') as f:
        f.writelines(logs)

if __name__ == '__main__':
    init()
    prepare_input()
    thread = threading.Thread(target=accept_client)
    thread.setDaemon(True)
    thread.start()
    run_server()
