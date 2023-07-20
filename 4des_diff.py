from des import Des, P_Table, PC2_Table, LOOP_Table, PC1_Table
import random
import numpy as np
from collections import defaultdict
import copy
from utils import bin2int, bin2hex, int2bin, int2hex, hex2bin, hex2int, xor
import itertools as it
import time
import tqdm
import datetime

class DifferentialCryptandysis:
  def __init__(self, des: Des, M, testnum=5) -> None:
    # testnum: 最终测试时，用于测试的次数，可以提高攻击的精度
    self.des = des
    self.N = des.N
    self.testnum = testnum
    self.STable = self.Sxor()
    self.M = M # 使用M次差分分析

    self.position1 = sorted([k for k in range(1, 57) if k not in PC2_Table]) # PC2_Table中丢失的位置
    self.position2 = sorted([k for k in range(1, 65) if k not in PC1_Table]) # 校验和的位置

    self.__D = Des(self.N)
    self.__P = [bin2hex([random.randint(0, 1) for _ in range(64)], 16) for _ in range(self.testnum)]
    self.__T = [self.des.encode(p) for p in self.__P]
    self.__K = None

    self.pbar = None

    self.dP = ['0000666600000000', '6666000000000000']
    self.prob_key = [[] for _ in range(8)]
    self.key_dict = [defaultdict(int), defaultdict(int)]
    self.key_pos = [[0, 1, 2, 3], [4, 5, 6, 7]]

  def Sxor(self):
    Sxor = [[[[] for _ in range(16)] for _ in range(64)] for _ in range(8)]
    for i in range(8):
      for B in range(64):
        for BB in range(64):
          inxor = B ^ BB
          outxor = bin2int(self.des.Sx(int2bin(B, 6), i)) ^ bin2int(self.des.Sx(int2bin(BB, 6), i))
          Sxor[i][inxor][outxor].append(B)
    return Sxor

  def analyze(self):
    print('==> Start analysing key...')
    for _ in tqdm.trange(self.M):
      for i in range(2):
        self.analyze_single(self.dP[i], self.key_pos[i], i)
    key = self.find_key() # 48bit
    print('==> Find the 48bit keys, start a search for the initial key...')
    self.pbar = tqdm.trange(2**len(self.position1))
    if not self.key_reverse(key): # 64bit
      print('Analyze fail!')
      exit(0)
    return self.__K

  def analyze_single(self, dP, pos, kd_i):
    # pos: 对应S盒的位置
    # initial_permutation操作是线性的，在分析时可以不考虑，直接生成F函数的输入即可
    P, PP, T, TT = self.generatePT(dP)
    L0, R0 = copy.deepcopy(P[0:32]), copy.deepcopy(P[32:64])
    LL0, RR0 = copy.deepcopy(PP[0:32]), copy.deepcopy(PP[32:64])
    L4, R4 = copy.deepcopy(T[0:32]), copy.deepcopy(T[32:64])
    LL4, RR4 = copy.deepcopy(TT[0:32]), copy.deepcopy(TT[32:64])

    E = self.des.E(L4)
    EE = self.des.E(LL4)
    IN = xor(E, EE)

    dR4 = xor(R4, RR4)
    OUT = dR4
    OUT = list(np.array(OUT)[np.argsort(P_Table)])

    Ex = [bin2int(E[i*6:(i+1)*6]) for i in range(8)]
    for i in pos:
      INx = bin2int(IN[i*6:(i+1)*6])
      OUTx = bin2int(OUT[i*4:(i+1)*4])
      for B in self.STable[i][INx][OUTx]:
        K = B ^ Ex[i]
        self.prob_key[i].append(K)

  def get_initial_key(self, key) -> bool:
    # 48bit -> 56bit
    key = list(np.array(key)[np.argsort(PC2_Table)])
    for p in self.position1: key.insert(p-1, 0) # 56bit
    offset = sum(LOOP_Table[0:self.N])
    combinations = list(it.product([0, 1], repeat=len(self.position1)))
    for comb in combinations:
      key_ = np.array(key)
      key_[np.array(self.position1)-1] = comb
      key_ = list(key_)
      t1 = key_[0:28-offset]
      t0 = key_[28-offset:28]
      t3 = key_[28:56-offset]
      t2 = key_[56-offset:56]
      key_ = t0 + t1 + t2 + t3 # 56bit
      # 56bit -> 64bit
      key_ = list(np.array(key_)[np.argsort(PC1_Table)])
      for i in self.position2:
        key_.insert(i-1, 0)
        for j in range(7):
          key_[i-1] ^= key_[i-j-2]
      key_ = bin2hex(key_, 16)
      
      OK = True
      self.__D.set_key(key_)
      for __P, __T in zip(self.__P, self.__T):
        T = self.__D.encode(__P)
        P = self.__D.decode(__T)
        if __T != T and __P != P:
          OK = False
          break
      if OK:
        self.__K = key_
        self.pbar.close()
        return True
      self.pbar.update(1)
    self.pbar.close()
    return False

  def key_reverse(self, key): # 48bit -> 56bit -> 64bit
    key = hex2bin(key, 48)
    return self.get_initial_key(key)

  def find_key(self):
    key_map = [defaultdict(int) for _ in range(8)]
    key = []
    for i in range(8):
      pk = self.prob_key[i]
      for k in pk:
        key_map[i][k] += 1
      m = max(key_map[i].values())
      temp = [k for k, v in key_map[i].items() if v == m]
      if len(temp) != 1:
        print('Try again!')
        exit(0)
      key.extend(int2bin(temp[0], 6))
    key = bin2hex(key, 16)
    return key

  def generatePT(self, dP):
    dP = hex2bin(dP, 64)
    P = [random.randint(0,1) for _ in range(64)]
    PP = xor(P, dP)
    T0, T1 = self.des.F(P[0:32], P[32:64])
    TT0, TT1 = self.des.F(PP[0:32], PP[32:64])
    T = T0 + T1
    TT = TT0 + TT1
    return P, PP, T, TT


if __name__ == '__main__':
  round = 4
  des = Des(round)
  # des.set_key('f93fde5a749fe21b')
  print('\nDifferential Cryptandysis of {}-round DES'.format(round))
  print('\n==> Built a Des!')
  dc = DifferentialCryptandysis(des, 2**4, 10)
  start = time.time()
  key = dc.analyze()
  end = time.time()
  during = datetime.timedelta(seconds=end-start)
  print('==> Finish analysing, it spends {}'.format(during))

  N = 1000
  print('\nOriginal key informations:')
  des.get_key()
  print('\nThe predicted key is {}, testing {} random plaintext...'.format(key, N))
  d = Des(round)
  d.set_key(key)
  for i in tqdm.trange(N):
    plaintext = bin2hex([random.randint(0, 1) for _ in range(64)], 16)
    ciphertext_gt = des.encode(plaintext) # groundtrue
    ciphertext_pre = d.encode(plaintext) # predict
    plaintext_pre = d.decode(ciphertext_gt)
    if ciphertext_gt != ciphertext_pre or plaintext != plaintext_pre:
      print('\nAttack unsuccessfully!')
      exit(0)
  print('\nAll test pass. Attack successfully!')
