import copy
import random
from utils import bin2int, bin2hex, int2bin, int2hex, hex2bin, hex2int, xor
import numpy as np
import copy

IP_Table = [ # 初置换, 64
	58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17,  9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
]

IPR_Table = [ # 逆初始置换, 64
	40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41,  9, 49, 17, 57, 25
]

E_Table = [ # E表，48
	32,  1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,
	8,  9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,  1
]

P_Table = [ # 置换选择, 32
	16, 7, 20, 21, 29, 12, 28, 17, 1,  15, 23, 26, 5,  18, 31, 10,
	2,  8, 24, 14, 32, 27, 3,  9, 19, 13, 30, 6,  22, 11, 4,  25
]

PC1_Table = [ # 置换选择1, 56
	57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
	10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
	14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4
]

PC2_Table = [ # 置换选择2, 48
	14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
	23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
	41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
]

LOOP_Table = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1] #密钥位移（左移次数）,16

S_Box = [ # 8个S盒 ，每个盒为4行16列, 8x4x16
	# 定义S1盒
	[[14,	 4,	13,	 1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7],
	 [0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8],
	 [4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0],
	 [15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13]],
	# 定义S2盒 
	[[15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10],
	 [3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5],
	 [0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15],
	 [13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9]],
	# 定义S3盒 
	[[10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8],
	 [13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1],
	 [13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7],
	 [1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12]],
	# 定义S4盒 
	[[7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15],
	 [13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9],
	 [10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4],
	 [3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14]],
	# 定义S5盒 
	[[2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9],
	 [14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6],
	 [4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14],
	 [11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3]],
	# 定义S6盒 
	[[12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11],
	 [10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8],
	 [9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6],
	 [4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13]],
	# 定义S7盒
	[[4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1],
	 [13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6],
	 [1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2],
	 [6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12]],
    # 定义S8盒
	[[13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7],
	 [1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2],
	 [7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8],
	 [2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11]]
]


class Des(object):
  def __init__(self, N=16) -> None:
    self.N = N  # 默认为16轮Des
    self.__secret_key = None
    self.__keys = None
    self.generateKey()
    self.set_key(self.__secret_key)

  def get_key(self): # 仅用于调试
    print('==============================================')
    print('secret key =', self.__secret_key)
    print('keys =', [bin2hex(k, 12) for k in self.__keys])
    # key = self.__keys[-1]
    # key = [bin2int(key[i*6:(i+1)*6]) for i in range(8)]
    # print(key)
    print('==============================================')
    # return self.__secret_key, key

  def generateKey(self): # hex, 16 length, 64 bit
    key = [random.randint(0, 1) for _ in range(64)]
    for i in [8, 16, 24, 32, 40, 48, 56, 64]: # 校验和的位置
      key[i-1] = 0
      for j in range(7):
        key[i-1] ^= key[i-j-2]
    self.__secret_key = bin2hex(key, 16)

  def check_key(self, key):
    key = hex2bin(key, 64)
    for i in [8, 16, 24, 32, 40, 48, 56, 64]: # 校验和的位置
      b = 0
      for j in range(7):
        b ^= key[i-j-2]
      if b != key[i-1]:
        print('Key is uncorrect, please reset!')
        exit(0)

  def set_key(self, key): # key: hex 16 length, 64bit
    # self.check_key(key)
    self.__secret_key = key    
    key = hex2bin(key, 64)
    key_ = [key[p-1] for p in PC1_Table] # 56bit
    self.__keys = []
    for i in range(self.N):
      offset = LOOP_Table[i]
      t0 = key_[0:offset]
      t1 = key_[offset:28]
      t2 = key_[28:offset+28]
      t3 = key_[offset+28:56]
      key_ = t1 + t0 + t3 + t2 # 56bit
      t = [key_[p - 1] for p in PC2_Table] # 48bit
      self.__keys.append(t)

  def encode(self, plaintext):
    return self.__en_de(plaintext, mode='encode')

  def decode(self, ciphertext):
    return self.__en_de(ciphertext, mode='decode')

  def initial_permutation(self, text):
    text_bin = format(int(text, 16), "064b")
    text_bin = [int(text_bin[p - 1]) for p in IP_Table]
    ltext_bin, rtext_bin = list(text_bin[0:32]), list(text_bin[32:64])
    return ltext_bin, rtext_bin
  
  def final_permutation(self, ltext_bin, rtext_bin):
    temp = ltext_bin
    ltext_bin = rtext_bin
    rtext_bin = temp

    text_bin = ltext_bin + rtext_bin
    text_bin = ''.join([str(text_bin[p-1]) for p in IPR_Table])
    text_hex = format(int(text_bin, 2), "016x")
    return text_hex

  def E(self, text_bin):
    e = [text_bin[ei-1] for ei in E_Table]
    return e
  
  def S(self, R): # 8个S盒操作，并输出R和S盒输出集合
    out = []
    for j in range(8):
      out.extend(self.Sx(R[j*6:(j+1)*6], j))
    return out
  
  def Sx(self, R, idx):
    box = S_Box[idx]
    row = R[0] * 2 + R[5]
    col = R[1] * 8 +  R[2] * 4 +  R[3] * 2 +  R[4]
    out = box[row][col]
    out = format(out, '04b')
    out = [int(i) for i in out]
    return out
  
  def F(self, ltext_bin, rtext_bin):
    for i in range(self.N): # 轮函数
      temp = copy.deepcopy(ltext_bin)
      ltext_bin = copy.deepcopy(rtext_bin)
      e = self.E(rtext_bin)
      e = xor(e, self.__keys[i])
      rtext_bin = self.S(e)
      rtext_bin = [rtext_bin[p-1] for p in P_Table]
      rtext_bin = xor(rtext_bin, temp)
    return ltext_bin, rtext_bin

  def __en_de(self, text, mode='encode'):
    if mode == 'decode':
      self.__keys.reverse()
    ltext_bin, rtext_bin = self.initial_permutation(text)
    ltext_bin, rtext_bin = self.F(ltext_bin, rtext_bin)
    text_hex = self.final_permutation(ltext_bin, rtext_bin)
    if mode == 'decode':
      self.__keys.reverse()
    return text_hex

if __name__ == '__main__':
  plaintext = 'b8fa82d1c42bd139' # hex, 16 length, 64 bit
  d = Des(8)
  # d.set_key('1234123412341234')
  d.get_key()
  ciphertext = d.encode(plaintext)
  print('ciphertext =', ciphertext)
  de_plaintext = d.decode(ciphertext)
  print('decode plaintext =', de_plaintext)
  if (plaintext.lower() == de_plaintext.lower()):
    print('Successfully decrypt!')
