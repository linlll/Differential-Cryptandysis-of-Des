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

    self.dP = ['405c000004000000', '000405c000002000']
    self.dR4 = ['04000000', '00002000']
    self.prob_key = [[] for _ in range(8)]
    self.key_dict = [defaultdict(int), defaultdict(int)]
    self.key_pos = [[1,4,5,6,7], [0,1,2,4,7]]

  def Sxor(self):
    Sxor = [[[[] for _ in range(16)] for _ in range(64)] for _ in range(8)]
    for i in range(8):
      for B in range(64):
        for BB in range(64):
          inxor = B ^ BB
          outxor = bin2int(self.des.Sx(int2bin(B, 6), i)) ^ bin2int(self.des.Sx(int2bin(BB, 6), i))
          Sxor[i][inxor][outxor].append(B)
    # self.guessP(Sxor)
    return Sxor

  def guessP(self, Sxor): # 调试程序，用于找出合适的两个差分
    for i in range(8):
      A = '0' * i + '6' + '0' * (7 - i)
      A = hex2bin(A, 32)

      E = self.des.E(A)
      E = [bin2int(E[j*6:(j+1)*6]) for j in range(8)]
      E = E[i]
      temp = [len(s) for s in Sxor[i][E]]
      m = max(temp)
      temp = [j for j in range(16) if temp[j] == m]
      B = []
      for t in temp:
        b = '0' * i + int2hex(t, 1) + '0' * (7 - i)
        b = hex2bin(b, 32)
        b = [b[p-1] for p in P_Table]
        B.append(b)

      APr = list(np.array(A)[np.argsort(P_Table)])
      APr = bin2hex(APr, 8)
      j = [j for j in range(8) if APr[j] != '0']
      print('A: {}, APr: {}, j: {}'.format(bin2hex(A, 8), APr, j))
      
      T = [[], []]
      for k in range(64):
        temp = [len(s) for s in Sxor[j[0]][k]]
        m = max(temp)
        temp = [p for p in range(16) if temp[p] == m]
        if int(APr[j[0]], 16) not in temp: continue
        T[0].append(k)
      for k in range(64):
        temp = [len(s) for s in Sxor[j[1]][k]]
        m = max(temp)
        temp = [p for p in range(16) if temp[p] == m]
        if int(APr[j[1]], 16) not in temp: continue
        T[1].append(k)
      
      for b in B:
        for t1 in T[0]:
          tt1 = int2bin(t1, 6)
          y11, y12 = [], []
          for q in range(64):
            temp = [len(s) for s in Sxor[(j[0]-1)%8][q]]
            m = np.argmax(temp)
            qq = int2bin(q, 6)
            if m == 0 and tt1[0] == qq[4] and tt1[1] == qq[5] and qq[0] == 0 and qq[1] == 0:
              y11.append(qq)
          for q in range(64):
            temp = [len(s) for s in Sxor[(j[0]+1)%8][q]]
            m = np.argmax(temp)
            qq = int2bin(q, 6)
            if m == 0 and tt1[0] == qq[4] and tt1[1] == qq[5] and qq[0] == 0 and qq[1] == 0:
              y12.append(qq)
          
          for t2 in T[1]:
            tt2 = int2bin(t2, 6)
            y21, y22 = [], []
            for q in range(64):
              temp = [len(s) for s in Sxor[(j[1]-1)%8][q]]
              m = np.argmax(temp)
              qq = int2bin(q, 6)
              if m == 0 and tt2[0] == qq[4] and tt2[1] == qq[5] and qq[0] == 0 and qq[1] == 0:
                y21.append(qq)
            for q in range(64):
              temp = [len(s) for s in Sxor[(j[1]+1)%8][q]]
              m = np.argmax(temp)
              qq = int2bin(q, 6)
              if m == 0 and tt2[0] == qq[4] and tt2[1] == qq[5] and qq[0] == 0 and qq[1] == 0:
                y22.append(qq)
            
            for yy11 in y11:
              for yy12 in y12:
                for yy21 in y21:
                  for yy22 in y22:
                    C = [int2bin(0, 4) for _ in range(8)]
                    C[j[0]] = tt1[1:5]
                    C[j[1]] = tt2[1:5]
                    C[(j[0]-1)%8] = yy11[1:5]
                    C[(j[0]+1)%8] = yy12[1:5]
                    C[(j[1]-1)%8] = yy21[1:5]
                    C[(j[1]+1)%8] = yy22[1:5]

                    temp = []
                    for c in C:
                      temp.extend(c)
                    C = temp

                    L = xor(b, C)
                    E = self.des.E(L)
                    E = [bin2int(E[l*6:(l+1)*6]) for l in range(8)]
                    pos = [l for l in range(8) if E[l] == 0]

                    print('B: {}, C: {}, L: {}, pos: {}, j: {}'.format(bin2hex(b, 8), bin2hex(C, 8), 
                                                                bin2hex(L, 8), pos, j))
      input()
    input()

  def analyze(self):
    print('==> Start analysing key...')
    for _ in tqdm.trange(self.M):
      for i in range(2):
        self.analyze_single(self.dP[i], self.key_pos[i], i)
    key = self.find_key() # 42bit
    print('==> Find the 42bit keys, the key[12:18] don\'t find yet.')
    print('==> Search the key[12:18] and start a search for the initial key...')
    if not self.key_reverse(key): # 64bit
      print('Analyze fail!')
      exit(0)
    return self.__K

  def analyze_single(self, dP, pos, kd_i):
    # pos: 对应S盒的位置
    # initial_permutation操作是线性的，在分析时可以不考虑，直接生成F函数的输入即可
    P, PP, T, TT = self.generatePT(dP)
    L8, R8 = copy.deepcopy(T[0:32]), copy.deepcopy(T[32:64])
    LL8, RR8 = copy.deepcopy(TT[0:32]), copy.deepcopy(TT[32:64])

    E = self.des.E(L8)
    EE = self.des.E(LL8)
    IN = xor(E, EE)

    dR8 = xor(R8, RR8)
    OUT = xor(dR8, hex2bin(self.dR4[kd_i], 32))
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
    for i in range(64):
      print('==> set key[12:18] = {}'.format(i))
      self.pbar = tqdm.trange(2**len(self.position1))
      key[3] = i
      key_ = 0
      for k in key:
        key_ *= 64
        key_ += k
      key_ = int2bin(key_, 48)
      if self.get_initial_key(key_):
        return True
    return False

  def find_key(self):
    key = [-1 for _ in range(8)]
    for i in range(2):
      m = max(self.key_dict[i].values())
      temp = [k for k, v in self.key_dict[i].items() if v == m]
      if len(temp) != 1 and i == 0:
        print('[0] try again!')
        exit(0)
      
      flag1 = False
      for k in temp:
        t = []
        for _ in range(len(self.key_pos[i])):
          t.append(k % 64)
          k //= 64
        flag2 = True
        for a, p in zip(t, reversed(self.key_pos[i])):
          if key[p] != -1 and key[p] != a:
            flag2 = False
            break
        if flag2:
          flag1 = True
          break
      if not flag1:
        print('[1] try again!')
        exit(0)

      for a, p in zip(t, reversed(self.key_pos[i])):
        key[p] = a

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
  round = 8
  des = Des(round)
  # des.set_key('f93fde5a749fe21b')
  print('\nDifferential Cryptandysis of {}-round DES'.format(round))
  print('\n==> Built a Des!')
  dc = DifferentialCryptandysis(des, 2**17, 10)
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
