def int2bin(x: int, length):
  b = format(x, '0{}b'.format(length))
  b = [int(i) for i in b]
  return b

def bin2int(b: list):
  x = [str(i) for i in b]
  x = int(''.join(x), 2)
  return x

def int2hex(x: int, length):
  h = format(x, '0{}x'.format(length))
  return h

def hex2int(h: str):
  return int(h, 16)

def hex2bin(h: str, length):
  b = format(int(h, 16), '0{}b'.format(length))
  b = [int(i) for i in b]
  return b

def bin2hex(b: list, length):
  b = [str(i) for i in b]
  h = format(int(''.join(b), 2), '0{}x'.format(length))
  return h

def xor(a, b):
  assert len(a) == len(b)
  c = [i ^ j for i, j in zip(a, b)]
  return c