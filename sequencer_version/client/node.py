import connections as cn
from threading import Thread
import config as cfg
import blocks_identity as bk
from wrappers import Index
current_time = -1
open_queries = {}
syncing = False
def main() -> None:
    t_socket = Thread(target=cn.socket_events,name='socket')
    t_commands = Thread(target=cn.commands,name='commands')
    t_socket.start()
    t_commands.start()

    # index = Index(cfg.db.misc_values.get(b"identity_bc_index"))-1
    # if index >= 0:
    #     bk.initiate_chain_sync(index)
    # else:
    #     bk.sync_next_block(Index(b"\x00\x00\x00\x00"))
if __name__ == "__main__":
    main()