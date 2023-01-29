import hashlib

NULL_CHAR = '255'
BIT_SHIFT_NUM = 20
# BYTE_SHIFT_NUM = |_BIT_SHIFT_NUM / 8_| = |_20/8_| = 3
BIT_SHIFT_MASK = 2 ** BIT_SHIFT_NUM - 1


def database_deserialize(querying, queried):
    # print("queried result: ", queried)
    result = queried.strip().split(',')
    if any([i == NULL_CHAR for i in result]):
        a, b = 'NULL', 'NULL'
    else:
        y, m, d, a = result
        b = f'20{int(y):02d}-{int(m):02d}-{int(d):02d}'
    return f"{querying.strip()},{b},{a}\n"


def database_serialize(raw):
    return '\n'.join([raw[2:4], raw[5:7], raw[8:10], raw[11:]])


def save_results(results, path='../../results/PIR_RESULTS.csv'):
    lines = ['id,register_date,age\n']
    lines.extend([database_deserialize(*result) for result in results.items()])
    with open(path, 'w') as f:
        f.writelines(lines)
    print(f"results saved at {path}")


def preprocess_id(index):
    hasher = hashlib.sha256()
    hasher.update(index.encode())
    big_int = int.from_bytes(hasher.digest(), 'big')
    n_out_of_all = big_int >> BIT_SHIFT_NUM
    one_out_of_n = big_int & BIT_SHIFT_MASK
    return n_out_of_all, one_out_of_n
