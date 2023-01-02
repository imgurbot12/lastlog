from struct import Struct
from typing import Any

def stringify(b: bytes) -> Any:
    if isinstance(b, bytes):
        return b.strip(b'\0').decode()
    return b

struct = Struct('hi32s4s32s256shhiii4i20s')
with open('/var/log/wtmp', 'rb') as f:
    offset  = 0
    content = f.read()
    while offset < len(content):
        record = list(map(stringify, struct.unpack_from(content, offset)))
        offset += struct.size
        print(record)

