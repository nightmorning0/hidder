import os
import tqdm
import queue
import ctypes
import multiprocessing
import random
import time
import logging
from pathlib import Path
from cryptography.fernet import Fernet


class Sealer:
    HEADER_BLOCK_SIZE = 10
    HEADER_FILE_NAME = 256
    BYTE_ORDER = "big"
    ENCODEING = "utf-8"
    MAX_DIRS_AT_SAME_LEVEL = 9999
    NAMEFILE_NAME = ".name"
    LOG_FLUSH_INTERVAL = 0.2
    def __init__(self, src:str, tgt:str, tk:str="", block_size:int=512) -> None:
        """_summary_

        Args:
            src (str): the source directory you want to seal/unseal.
            tgt (str): the target directory you want to seal/unseal.
            tk (str, optional): the key to be used in the process. Defaults to "".
            block_size (int, optional): the size(MB) of cache to read file. Defaults to 512.
        """
        self.src = Path(src)
        self.tgt = Path(tgt)
        if tk == "":
            self.tk = Fernet.generate_key()
            with open("token", "wb") as fp:
                fp.write(self.tk)
        else:
            with open(tk, "rb") as fp:
                self.tk = fp.read()
        self.fernet = Fernet(self.tk)
        self.block_size = block_size
        self.logger = logging.getLogger("Sealer")
    
    def encrypt_singleprocess(self):
        path_queue = queue.Queue()
        dir_queue = queue.LifoQueue()

        for child_p in self.src.glob("*"):
            path_queue.put(child_p)

        while not path_queue.empty():
            p = path_queue.get()
            for child_p in p.glob("*"):
                path_queue.put(child_p)
            
            if p.is_dir():
                new_p = self.tgt/p.relative_to(self.src)
                new_p.mkdir(exist_ok=True, parents=True)
                dir_queue.put(new_p)

            elif p.is_file():
                new_p = self.tgt/self.encr_path(p.relative_to(self.src))
                Sealer.mk_partent_dir(new_p)
                self.encr_file(p, new_p)                
            else:
                raise
        
        while(not dir_queue.empty()):
            p = dir_queue.get()
            self.encr_dir_name(p)
            
    def decrypt_singleprocess(self):
        path_queue = queue.Queue()
        dir_queue = queue.LifoQueue()

        for child_p in self.src.glob("*"):
            path_queue.put(child_p)

        while not path_queue.empty():
            p = path_queue.get()
            for child_p in p.glob("*"):
                path_queue.put(child_p)

            if p.is_dir():
                new_p = self.tgt/p.relative_to(self.src)
                new_p.mkdir(exist_ok=True, parents=True)
                dir_queue.put(new_p)

            elif p.is_file():
                new_p = self.tgt/self.decr_path(p.relative_to(self.src))
                Sealer.mk_partent_dir(new_p)
                self.decr_file(p, new_p)
                # self.decr_file_static(p, new_p, self.tk, self.HEADER_BLOCK_SIZE, self.BYTE_ORDER)

        while(not dir_queue.empty()):
            p = dir_queue.get()
            self.decr_dir_name(p)

    def prepare_queues(self, mode):
        path_queue = queue.Queue()
        dir_queue = queue.LifoQueue()
        file_pair_queue = multiprocessing.Queue()
        total_file_pair = 0

        for child_p in self.src.glob("*"):
            path_queue.put(child_p)

        self.logger.info("reading file list")
        while not path_queue.empty():
            p = path_queue.get()
            for child_p in p.glob("*"):
                path_queue.put(child_p)
            
            if p.is_dir():
                new_p = self.tgt/p.relative_to(self.src)
                new_p.mkdir(exist_ok=True, parents=True)
                dir_queue.put(new_p)

            elif p.is_file():
                if mode == "encrypt":
                    new_p = self.tgt/self.encr_path(p.relative_to(self.src))
                elif mode == "decrypt":
                    new_p = self.tgt/self.decr_path(p.relative_to(self.src))
                else:
                    raise
                Sealer.mk_partent_dir(new_p)
                file_pair_queue.put([p, new_p])
                total_file_pair += 1                
            else:
                raise
        self.logger.info(f"{total_file_pair} files in total founded")
        return dir_queue, file_pair_queue, total_file_pair

    def encrypt_multiprocesses(self, n_workers=4):
        """Use Fernet to encrypt queue.

        Args:
            n_workers (int, optional): the num of process to encrypt. Defaults to 4.
        """
        dir_queue, file_pair_queue, total_file_pair = self.prepare_queues("encrypt")
        
        self.logger.info("encrypt files")
        workers = []
        counter = multiprocessing.Value(ctypes.c_longlong, lock=True)
        for i in range(n_workers):
            proc = multiprocessing.Process(
                target = Sealer.encr_queue,
                name = f"file-encryption-proc-{i}",
                args = [file_pair_queue, self.tk, self.block_size, self.HEADER_BLOCK_SIZE, self.BYTE_ORDER, counter]
            )
            proc.start()
            workers.append(proc)
            self.logger.info(f"encryption process {i} started.")

        pbar = tqdm.tqdm(total=total_file_pair)
        while counter.value < total_file_pair:
            with counter.get_lock():
                pbar.update(counter.value - pbar.n)
            time.sleep(self.LOG_FLUSH_INTERVAL)
        pbar.update(counter.value - pbar.n)
        pbar.close()

        for worker in workers:
            worker.join()
        
        self.logger.info("encrypt directories")
        while(not dir_queue.empty()):
            p = dir_queue.get()
            self.encr_dir_name(p)        

    def decrypt_multiprocesses(self, n_workers=4):
        """Use Fernet to decrypt queue.

        Args:
            n_workers (int, optional): the num of process to decrypt. Defaults to 4.
        """
        dir_queue, file_pair_queue, total_file_pair = self.prepare_queues("decrypt")

        self.logger.info("decrypt files")
        workers = []
        counter = multiprocessing.Value(ctypes.c_longlong, lock=True)
        for i in range(n_workers):
            proc = multiprocessing.Process(
                target = Sealer.decr_queue,
                name = f"file-decryption-proc-{i}",
                args = [file_pair_queue, self.tk, self.HEADER_BLOCK_SIZE, self.BYTE_ORDER, counter]
            )
            proc.start()
            workers.append(proc)
            self.logger.info(f"decryption process {i} started.")

        pbar = tqdm.tqdm(total=total_file_pair)
        while counter.value < total_file_pair:
            with counter.get_lock():
                pbar.update(counter.value - pbar.n)
            time.sleep(self.LOG_FLUSH_INTERVAL)
        pbar.update(counter.value - pbar.n)
        pbar.close()

        for worker in workers:
            worker.join()
        
        self.logger.info("decrypt directories")
        while(not dir_queue.empty()):
            p = dir_queue.get()
            self.decr_dir_name(p)   

    def encr_str(self, s):
        return str(
            self.fernet.encrypt(bytes(s, encoding=self.ENCODEING)), 
            encoding=self.ENCODEING)
    
    def decr_str(self, s):
        return str(
            self.fernet.decrypt(bytes(s, encoding=self.ENCODEING)), 
            encoding=self.ENCODEING)
    
    def encr_path(self, p):
        return p.parent/self.encr_str(p.name)
        
    def decr_path(self, p):
        return p.parent/self.decr_str(p.name)
    
    def encr_file(self, src, tgt):
        if src == tgt:
            tgt = tgt.parent/(tgt.name + ".tmp")
            remove_flag = True
        else:
            remove_flag = False

        reader = open(src, "rb")
        writer = open(tgt, "wb")

        data = reader.read(self.block_size)
        new_data = self.fernet.encrypt(data)
        encr_block_size = len(new_data)
        writer.write(encr_block_size.to_bytes(self.HEADER_BLOCK_SIZE, self.BYTE_ORDER))
        writer.write(new_data)

        data = reader.read(self.block_size)
        while len(data) != 0:
            new_data = self.fernet.encrypt(data)
            writer.write(new_data)
            data = reader.read(self.block_size)
        
        reader.close()
        writer.close()

        if remove_flag:
            os.remove(src)
            tgt.rename(src)

    def decr_file(self, src, tgt):
        if src == tgt:
            tgt = tgt.parent/(tgt.name + ".tmp")

        reader = open(src, "rb")
        writer = open(tgt, "wb")

        encr_block_size = int.from_bytes(
            reader.read(self.HEADER_BLOCK_SIZE),
            self.BYTE_ORDER,
            signed=False
        ) 
        
        data = reader.read(encr_block_size)
        while len(data) != 0:
            new_data = self.fernet.decrypt(data)
            writer.write(new_data)
            data = reader.read(encr_block_size)
        
        reader.close()
        writer.close()

        if src == tgt:
            os.remove(src)
            tgt.rename(src)

    def encr_dir_name(self, dir_path):
        name = dir_path.name
        name_file_path = dir_path/self.encr_str(self.NAMEFILE_NAME)
        with open(name_file_path, "w") as fp:
            fp.write(name)
        
        self.encr_file(name_file_path, name_file_path)
        
        new_name = str(random.randint(0, self.MAX_DIRS_AT_SAME_LEVEL))
        while (dir_path.parent/new_name).exists():
            new_name = str(random.randint(0, self.MAX_DIRS_AT_SAME_LEVEL))
        
        os.rename(dir_path, dir_path.parent/new_name)
    
    def decr_dir_name(self, dir_path):
        name = dir_path.name
        name_file_path = dir_path/self.NAMEFILE_NAME
        if (name_file_path).exists():
            with open(name_file_path, "r") as fp:
                name = fp.read()
            os.remove(name_file_path)
            os.rename(dir_path, dir_path.parent/name)

    @staticmethod
    def mk_partent_dir(p):
        Path(p).parent.mkdir(exist_ok=True, parents=True)
    
    @staticmethod
    def ch_root(p, src, tgt):
        return Path(tgt)/Path(p).relative_to(src)

    @staticmethod
    def encr_file_static(src, tgt, tk, block_size, header_block_size, byte_order):
        if src == tgt:
            tgt = tgt.parent/(tgt.name + ".tmp")
            remove_flag = True
        else:
            remove_flag = False
        fernet = Fernet(tk)
        reader = open(src, "rb")
        writer = open(tgt, "wb")

        data = reader.read(block_size)
        new_data = fernet.encrypt(data)
        encr_block_size = len(new_data)
        writer.write(encr_block_size.to_bytes(header_block_size, byte_order))
        writer.write(new_data)
        
        data = reader.read(block_size)
        while len(data) != 0:
            new_data = fernet.encrypt(data)
            writer.write(new_data)
            data = reader.read(block_size)
        
        reader.close()
        writer.close()

        if remove_flag:
            os.remove(src)
            tgt.rename(src)
    
    @staticmethod
    def decr_file_static(src, tgt, tk, header_block_size, byte_order):
        fernet = Fernet(tk)
        if src == tgt:
            tgt = tgt.parent/(tgt.name + ".tmp")

        reader = open(src, "rb")
        writer = open(tgt, "wb")

        encr_block_size = int.from_bytes(
            reader.read(header_block_size),
            byte_order,
            signed=False
        ) 
        
        data = reader.read(encr_block_size)
        while len(data) != 0:
            new_data = fernet.decrypt(data)
            writer.write(new_data)
            data = reader.read(encr_block_size)
        
        reader.close()
        writer.close()

        if src == tgt:
            os.remove(src)
            tgt.rename(src)

    @staticmethod
    def encr_queue(queue, tk, block_size, header_block_size, byte_order, counter):
        try:
            pair = queue.get_nowait()
        except:
            pair = None

        while not pair is None:
            src, tgt = pair
            Sealer.encr_file_static(src, tgt, tk, block_size, header_block_size, byte_order)
            with counter.get_lock():
                counter.value += 1
            try:
                pair = queue.get_nowait()
            except:
                pair = None
    
    @staticmethod
    def decr_queue(queue, tk, header_block_size, byte_order, counter):
        try:
            pair = queue.get_nowait()
        except:
            pair = None

        while not pair is None:
            src, tgt = pair
            Sealer.decr_file_static(src, tgt, tk, header_block_size, byte_order)
            with counter.get_lock():
                counter.value += 1
            try:
                pair = queue.get_nowait()
            except:
                pair = None
        

if __name__ == "__main__":


    logging.basicConfig(level=logging.INFO)
    # s = Sealer("test", "test_out")
    # s.encrypt()
    # s.encrypt_multiprocesses(8)

    s = Sealer("test_out", "test_out2", "token")
    s.decrypt_multiprocesses(8)