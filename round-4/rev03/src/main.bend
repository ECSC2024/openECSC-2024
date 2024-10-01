object Block { b1, b2 }


def Block/0(x):
  open Block: x
  return x.b1


def Block/1(x):
  open Block: x
  return x.b2


object Pair { _0, _1 }


def Pair/0(x):
  open Pair: x
  return x._0


def Pair/1(x):
  open Pair: x
  return x._1

def ror(x, y):
  return x >> y | x << (16 - y) & 0xFFFF


def rol(x, y):
  return x << y | x >> (16 - y) & 0xFFFF


def add(x, y):
  return x + y


def sub(x, y):
  return x - y


def mul(x, y):
  return x * y


def xor(x, y):
  return x ^ y


def div(x, y):
  return x / y


def mod(x, y):
  return x % y
# Takes two numbers and returns the result of x**y
def pow(x, y):
  bend p = 1, i = 0:
    when i < y:
      return fork(p * x, i + 1)
    else:
      return p


# Takes a number and returns it as tree of bits
def to_bin_tree(x):
  bend bitsize = 16, n = x:
    when bitsize > 2:
      return ![
        fork(bitsize / 2, n >> (bitsize / 2)),
        fork(bitsize / 2, n & ((1 << (bitsize / 2)) - 1))
      ]
    else:
      return ![!div(n, bitsize), !mod(n, bitsize)]


# Takes a tree of bits and returns a tree of Pair(index, bit)
def with_index_inv(tree):
  idx = 0
  fold tree with idx:
    case Tree/Node:
      return ![tree.left(idx * 2 + 1), tree.right(idx * 2 + 0)]
    case Tree/Leaf:
      return !Pair(idx, tree.value)


def with_index(tree):
  idx = 0
  fold tree with idx:
    case Tree/Node:
      return ![tree.left(idx * 2 + 0), tree.right(idx * 2 + 1)]
    case Tree/Leaf:
      return !Pair(idx, tree.value)


def get_index(tree, idx):
  step = 8
  fold tree with idx, step:
    case Tree/Node:
      if idx / step == 0:
        return tree.left(idx % step, step / 2)
      else:
        return tree.right(idx % step, step / 2)
    case Tree/Leaf:
      return tree.value


# Takes a tree of bits wrapped in Pair with (index, bit) and returns a tree of Pair(pow(2, index), bit)
def index_2_power(tree):
  fold tree:
    case Tree/Node:
      return Tree/Node(tree.left, tree.right)
    case Tree/Leaf:
      open Pair: tree.value
      return !Pair(pow(2,tree.value._0), tree.value._1)


# Takes a tree of bits and return the number it represents
def from_bin_tree(tree):
  _t = index_2_power(with_index_inv(tree))
  fold _t:
    case Tree/Node:
      return _t.left + _t.right
    case Tree/Leaf:
      open Pair: _t.value
      return _t.value._0 * _t.value._1


# Takes a tree of bits and rotates it to the right by y
def tree_ror(tree, y):
  _t = with_index(tree)

  fold _t:
    case Tree/Node:
      return ![_t.left, _t.right]
    case Tree/Leaf:
      open Pair: _t.value
      el = get_index(tree, (_t.value._0 - y) % 16)
      return Tree/Leaf(el)


# Takes a tree of bits and rotates it to the left by y
def tree_rol(tree, y):
  _t = with_index(tree)

  fold _t:
    case Tree/Node:
      return ![_t.left, _t.right]
    case Tree/Leaf:
      open Pair: _t.value
      el = get_index(tree, (_t.value._0 + y) % 16)
      return Tree/Leaf(el)


# Takes two trees of bits and returns a tree of bits with the xor of the two trees
def tree_xor(tree1, tree2):
  _t1 = with_index(tree1)

  fold _t1:
    case Tree/Node:
      return ![_t1.left, _t1.right]
    case Tree/Leaf:
      open Pair: _t1.value
      el = get_index(tree2, _t1.value._0)
      return Tree/Leaf(_t1.value._1 ^ el)


def tree_mod_add(tree1, tree2):
  x = from_bin_tree(tree1)
  y = from_bin_tree(tree2)
  return to_bin_tree((x + y) & 0xFFFF)


# One round of Speck, rounds the plaintext and the key, return the new key blocks and the ciphertext blocks
def round(k, x, i):
  open Block: k
  open Block: x

  ox1 = tree_xor(
    tree_mod_add(tree_ror(x.b1, 8), x.b2),
    k.b2
  )
  
  ox2 = tree_xor(
    tree_rol(x.b2, 3),
    ox1
  )

  kx1 = tree_xor(
    tree_mod_add(tree_ror(k.b1, 8), k.b2),
    to_bin_tree(i)
  )
  kx2 = tree_xor(
    tree_rol(k.b2, 3),
    kx1
  )

  return Pair(
    Block { b1: kx1, b2: kx2 }, 
    Block { b1: ox1, b2: ox2 }
  )


def encrypt(key1, key2, plaintext1, plaintext2):
  bend i = 0, k1 = key1, k2 = key2, x1 = plaintext1, x2 = plaintext2:
    when i < 22:
      # round i
      res = round(
        Block { b1: k1, b2: k2 },
        Block { b1: x1, b2: x2 },
        i
      )
      k = Pair/0(res)
      x = Pair/1(res)

      open Block: k
      open Block: x
      return fork(i + 1, k.b1, k.b2, x.b1, x.b2)
    else:
      return Pair(
        Block(
          from_bin_tree(k1),
          from_bin_tree(k2)
        ),
        Block(
          from_bin_tree(x1),
          from_bin_tree(x2)
        )
      )

object Quadruple { _0, _1, _2, _3 }


def main:
  t = TREE_INPUT

  fold t:
    case Tree/Node:
      return ![
        t.left,
        t.right
      ]
    case Tree/Leaf:
      open Quadruple: t.value
      res = encrypt(
        to_bin_tree(t.value._0),
        to_bin_tree(t.value._1),
        to_bin_tree(t.value._2),
        to_bin_tree(t.value._3)
      )

      open Pair: res
      ct = Pair/1(res)
      open Block: ct
      return Pair(to_bin_tree(ct.b1), to_bin_tree(ct.b2))  
