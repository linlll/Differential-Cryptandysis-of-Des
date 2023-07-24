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

    self.dP = ['405c000004000000', '1a04008000004000']
    self.dR3 = ['00540000', '1a000000']
    self.prob_key = [[] for _ in range(8)]
    self.key_dict = [defaultdict(int), defaultdict(int)]
    # self.key_pos = [[0,2,3,4,5,6,7], [0,1,2,3,5,6,7]] # 实际的位置
    # 由于回溯时间复杂度太大，所以对key的位置的重复部分做了消减，可能会影响结果
    self.key_pos = [[4,5,6,7], [0,1,2,3]]
    # self.key_pos = [[0,2,3,4,5,6,7], [0,1,2,3,5,6,7]]

  def Sxor(self):
    Sxor = [[[[] for _ in range(16)] for _ in range(64)] for _ in range(8)]
    for i in range(8):
      for B in range(64):
        for BB in range(64):
          inxor = B ^ BB
          outxor = bin2int(self.des.Sx(int2bin(B, 6), i)) ^ bin2int(self.des.Sx(int2bin(BB, 6), i))
          Sxor[i][inxor][outxor].append(B)
    # print([len(s) for s in Sxor[3][50]])
    # input()
    # self.guessP(Sxor)
    return Sxor

  def guessP(self, Sxor): # 调试程序，用于找出合适的两个差分
    for i in range(8):
      P = '0' * i + '4' + '0' * (7 - i)
      print(P)
      P = hex2bin(P, 32)
      C = list(np.array(P)[np.argsort(P_Table)])
      C = [bin2int(C[j*4:(j+1)*4]) for j in range(8)]
      print(C)
      pos = [j for j in range(8) if C[j] != 0]
      pos = pos[0]
      print(pos)
      B = []
      for j in range(64):
        temp = [len(s) for s in Sxor[pos][j]]
        m = max(temp)
        temp = [k for k in range(16) if temp[k] == m]
        if C[pos] in temp:
          temp1 = [0 for k in range(8)]
          temp1[pos] = j
          temp2 = int2bin(j, 6)
          temp3 = [0,0,0,0,0,0]
          temp3[4] = temp2[0]
          temp3[5] = temp2[1]
          temp1[(pos-1)%8] = bin2int(temp3)
          temp3 = [0,0,0,0,0,0]
          temp3[0] = temp2[4]
          temp3[1] = temp2[5]
          temp1[(pos+1)%8] = bin2int(temp3)
          B.append(temp1)
      print(B)
      Btmp = []
      for b in B:
        pos1 = []
        d = defaultdict(int)
        for j in range(8):
          if j == pos: continue
          if b[j] == 0: continue
          pos1.append(j)
          d[j] = []
          for k in range(4):
            kk = int2bin(k, 2)
            temp1 = int2bin(b[j], 6)
            temp1[2:4] = kk
            temp1 = bin2int(temp1)
            temp = [len(s) for s in Sxor[j][temp1]]
            m = max(temp)
            temp = [q for q in range(16) if temp[q] == m]
            if 0 in temp:
              d[j].append(temp1)
        print(d)
        if len(pos1) == 1 and len(d[pos1[0]]) != 0:
          for item in d[pos1[0]]:
            b[pos1[0]] = item
            Btmp.append(b)
        if len(pos1) == 2 and len(d[pos1[0]]) != 0 and len(d[pos1[1]]) != 0:
          for item0 in d[pos1[0]]:
            b[pos1[0]] = item0
            for item1 in d[pos1[1]]:
              b[pos1[1]] = item1
              Btmp.append(b)
      B = Btmp
      print(B)
      R = []
      for b in B:
        temp = [int2bin(bb, 6) for bb in b]
        temp1 = []
        for t in temp: temp1.extend(t[1:5])
        R.append(bin2hex(temp1, 8))
      for r in R:
        print(r)
      input()

    print('Done')
    input()

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
    L7, R7 = copy.deepcopy(T[0:32]), copy.deepcopy(T[32:64])
    LL7, RR7 = copy.deepcopy(TT[0:32]), copy.deepcopy(TT[32:64])

    E = self.des.E(L7)
    EE = self.des.E(LL7)
    IN = xor(E, EE)

    dR7 = xor(R7, RR7)
    OUT = xor(dR7, hex2bin(self.dR3[kd_i], 32))
    OUT = list(np.array(OUT)[np.argsort(P_Table)])

    Ex = [bin2int(E[i*6:(i+1)*6]) for i in range(8)]

    for i in pos:
      INx = bin2int(IN[i*6:(i+1)*6])
      OUTx = bin2int(OUT[i*4:(i+1)*4])
      if len(self.STable[i][INx][OUTx]) == 0:
        return

    self.prob_key = [[] for _ in range(8)]
    for i in pos:
      INx = bin2int(IN[i*6:(i+1)*6])
      OUTx = bin2int(OUT[i*4:(i+1)*4])
      for B in self.STable[i][INx][OUTx]:
        K = B ^ Ex[i]
        self.prob_key[i].append(K)
    self.backtracking(pos, 0, [], kd_i)
  
  def backtracking(self, pos, i, key: list, kd_i):
    if i >= len(pos):
      if len(key) != len(pos): return
      k_ = 0
      for k in key:
        k_ *= 64
        k_ += k
      self.key_dict[kd_i][k_] += 1
      return
    
    for pk in self.prob_key[pos[i]]:
      key.append(pk)
      self.backtracking(pos, i+1, key, kd_i)
      key.pop()

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
    key = [0 for _ in range(8)]
    for i in range(2):
      m = max(self.key_dict[i].values())
      temp = [k for k, v in self.key_dict[i].items() if v == m]
      if len(temp) != 1:
        print('[0] try again!')
        exit(0)
      k = temp[0]
      t = []
      while k != 0:
        t.append(k % 64)
        k //= 64
      if len(t) != len(self.key_pos[i]):
        print('[1] try again!')
        exit()
      for a, p in zip(t, reversed(self.key_pos[i])):
        key[p] = a

    key_ = 0
    for k in key:
      key_ *= 64
      key_ += k
    key = int2hex(key_, 16)
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
  round = 7
  des = Des(round)
  # des.set_key('f93fde5a749fe21b')
  print('\nDifferential Cryptandysis of {}-round DES'.format(round))
  print('\n==> Built a Des!')
  dc = DifferentialCryptandysis(des, 2**15, 10)
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
