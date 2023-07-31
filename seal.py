import os
import tqdm
import queue
import multiprocessing
import random

from pathlib import Path
from cryptography.fernet import Fernet

class Sealer:
    HEADER_BLOCK_SIZE = 10
    BYTE_ORDER = "big"
    ENCODEING = "utf-8"
    MAX_DIRS_AT_SAME_LEVEL = 9999
    NAMEFILE_NAME = ".name"
    def __init__(self, src, tgt, tk="", block_size=512) -> None:
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
    
    def encr_content(self):
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
            
    def decr_content(self):
        path_queue = queue.Queue()
        dir_queue = queue.LifoQueue()

        for child_p in self.src.glob("*"):
            path_queue.put(child_p)

        while not path_queue.empty():
            p = path_queue.get()
            print(p)
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



            

s = Sealer("test", "test_out", "token")
s.encr_content()

s = Sealer("test_out", "test_out2", "token")
s.decr_content()