#!/usr/bin/env python
# -*- coding: utf-8 -*-

from hashlib import sha256
import random
import time
import codecs
import struct


class Minebench:
    @staticmethod
    def get_score(times=50):
        final_score = 0.
        for _ in range(times):
            filename = 'blocks.csv'
            no_lines = InputUtils.get_file_lines(filename)

            start_time = FormatUtils.current_timestamp_in_millis()
            Minebench.run(**{'filename': filename, 'rows_no': no_lines, 'bits': 0x1F888888, 'sequential_nonce': True})
            total_millis = FormatUtils.current_timestamp_in_millis() - start_time

            score = int(no_lines * 10e6 / total_millis)
            final_score += score

        return int(final_score / times)

    @staticmethod
    def get_block_header(row, bits=0x1D00FFFF, sequential_nonce=False):
        # Line to dict
        row = Minebench.get_dict_from_file_line(row)

        # Merkle root from the block's raw transactions
        txs = row['tx'].split(':')
        merkle_root = Minebench.get_merkle_root(txs)

        return BlockHeader(ver=int(row['ver']),
                           prev_block=row['prev_block'],
                           merkle_root=merkle_root,
                           time=int(row['time']),
                           bits=bits,
                           sequential_nonce=sequential_nonce)

    @staticmethod
    def get_merkle_root(txs):
        txs_hashes = []
        for tx in txs:
            txs_hashes.append(FormatUtils.hex_to_sha256_sha256(tx))

        merkle_hashes = txs_hashes
        while len(merkle_hashes) > 1:
            merkle_hashes_len = len(merkle_hashes)
            new_merkle_hashes = []
            for i in range(0, merkle_hashes_len, 2):
                if merkle_hashes_len > i + 1:
                    h1 = FormatUtils.sha256_to_hex_little_endian(merkle_hashes[i])
                    h2 = FormatUtils.sha256_to_hex_little_endian(merkle_hashes[i + 1])
                    new_merkle_hashes.append(FormatUtils.hex_to_sha256_sha256(h1 + h2))
                    continue
                elif merkle_hashes_len == i + 1:
                    h1 = FormatUtils.sha256_to_hex_little_endian(merkle_hashes[i])
                    new_merkle_hashes.append(FormatUtils.hex_to_sha256_sha256(h1 + h1))
                    continue
                new_merkle_hashes.append(FormatUtils.hex_to_sha256_sha256(merkle_hashes[i]))
            merkle_hashes = new_merkle_hashes

        return merkle_hashes[0]

    @staticmethod
    def get_dict_from_file_line(line):
        if type(line) == str:
            line = line.strip().split(',')
        return {'ver': line[0], 'prev_block': line[1], 'time': line[2], 'tx': line[3]}

    @staticmethod
    def run(
            filename,
            rows_no,
            bits=0x1D00FFFF,
            sequential_nonce=False,
    ):
        random.seed(1984)
        with open(filename, 'r') as file:
            for i in range(0, rows_no):
                try:
                    row = next(file)
                except StopIteration:
                    break

                Minebench.get_block_header(row, bits, sequential_nonce).mine()


class InputUtils:
    @staticmethod
    def get_file_lines(filename):
        with open(filename, 'r') as file:
            no_lines = 0
            try:
                while (next(file)):
                    no_lines += 1
            except StopIteration:
                pass
            return no_lines

    @staticmethod
    def forward_file_lines(file_handler, lines_no):
        for _ in range(lines_no):
            try:
                next(file_handler)
            except StopIteration:
                return


class FormatUtils:
    @staticmethod
    def swap_hex(string):
        swapped_string = ''
        for i in range(0, len(string), 2):
            swapped_string += string[i + 1] + string[i]
        return swapped_string

    @staticmethod
    def sha256_to_hex_little_endian(string):
        return FormatUtils.swap_hex(string[::-1])

    @staticmethod
    def uint32_to_hex_little_endian(integer):
        return codecs.encode(struct.pack('<I', integer), 'hex').decode('utf-8')

    @staticmethod
    def uint32_to_hex_big_endian(integer):
        return codecs.encode(struct.pack('>I', integer), 'hex').decode('utf-8')

    @staticmethod
    def uint256_to_hex_big_endian(integer):
        string = str(hex(integer))[2:]
        padding = int(64 - len(string)) * '0'
        return padding + string

    @staticmethod
    def hex_to_bin(string):
        return bytearray.fromhex(string)

    @staticmethod
    def bin_to_hex(array):
        return codecs.encode(array, 'hex')

    @staticmethod
    def hex_to_int(string):
        return int(string, 16)

    @staticmethod
    def current_timestamp_in_seconds():
        return int(round(time.time()))

    @staticmethod
    def current_timestamp_in_millis():
        return int(round(time.time() * 1000))

    @staticmethod
    def bin_to_sha256_sha256_bin(header_bin):
        first_hash_bin = sha256(bytes(header_bin)).digest()
        second_hash_bin = sha256(first_hash_bin).digest()[::-1]  # little-endian
        return second_hash_bin

    @staticmethod
    def bin_to_sha256_sha256(header_bin):
        second_hash = codecs.encode(FormatUtils.bin_to_sha256_sha256_bin(header_bin), 'hex').decode('utf-8')
        return second_hash

    @staticmethod
    def hex_to_sha256_sha256(string):
        header_bin = FormatUtils.hex_to_bin(string)
        second_hash = FormatUtils.bin_to_sha256_sha256(header_bin)
        return second_hash


class BlockHeader:
    def __init__(self, ver, prev_block, merkle_root, time, bits, nonce=None, sequential_nonce=True):
        self.ver = int(ver)  # Block version number (4 bytes)
        # Hash of the previous block header (32 bytes)
        self.prev_block = prev_block
        # Hash based on all of the transactions in the block (32 bytes)
        self.merkle_root = merkle_root
        self.time = int(time)  # Timestamp in seconds (4 bytes)
        self.bits = int(bits)  # Current target in compact format (4 bytes)
        self.sequential_nonce = sequential_nonce
        self.nonce = 0  # 32-bit number (starts at 0, 4 bytes)
        self.used_nonces = set()
        self.header_bin = self._get_bin()

    def mine(self):
        network_target = self._get_target()
        network_target = FormatUtils.hex_to_bin(network_target)

        start_time = FormatUtils.current_timestamp_in_millis()
        attempts = 1

        current_hash = self._get_hash(self.header_bin)
        while (current_hash > network_target):
            self._set_new_nonce()
            current_hash = self._get_hash(self.header_bin)
            attempts += 1

        current_hash = FormatUtils.bin_to_hex(current_hash)

        return current_hash

    def _get_target(self):
        bits_big_endian_hex = FormatUtils.uint32_to_hex_big_endian(self.bits)
        exp = FormatUtils.hex_to_int(bits_big_endian_hex[:2])  # 8 bits
        coeff = FormatUtils.hex_to_int(bits_big_endian_hex[2:])  # 24 bits
        target = coeff * 2**(8 * (exp - 3))
        return FormatUtils.uint256_to_hex_big_endian(target)

    def _get_bin(self):
        return FormatUtils.hex_to_bin(self._get_hex())

    def _get_hex(self):
        return FormatUtils.uint32_to_hex_little_endian(self.ver) \
            + FormatUtils.sha256_to_hex_little_endian(self.prev_block) \
            + FormatUtils.sha256_to_hex_little_endian(self.merkle_root) \
            + FormatUtils.uint32_to_hex_little_endian(self.time) \
            + FormatUtils.uint32_to_hex_little_endian(self.bits) \
            + FormatUtils.uint32_to_hex_little_endian(self.nonce)

    def _get_hash(self, header_bin):
        return FormatUtils.bin_to_sha256_sha256_bin(header_bin)

    def _set_new_nonce(self):
        if self.sequential_nonce:
            self.nonce += 1
            self.header_bin[-4:] = struct.pack("<I", self.nonce)
            return

        while (True):
            nonce = random.randint(0, 0x7FFFFFFF)
            if not nonce in self.used_nonces:
                self.used_nonces.add(nonce)
                self.nonce = nonce
                self.header_bin[-4:] = struct.pack("<I", self.nonce)
                break


if __name__ == "__main__":
    print(Minebench.get_score())
