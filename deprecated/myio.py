import pickle
import scipy.io as sio

# return name.suffix if name doesn't have this suffix
def add_suffix(name, suffix):
    suffix = '.' + suffix
    if name.endswith(suffix):
        return name
    return name + suffix

def save_matrix(name, matrix):
    name = add_suffix(name, 'mat')
    sio.savemat(name, mdict={'data': matrix})

def load_matrix(name):
    name = add_suffix(name, 'mat')
    mat = sio.loadmat(name)
    return mat['data']

def save_mat(name, mdict):
    sio.savemat(name, mdict=mdict)

def load_mat(name):
    name = add_suffix(name, 'mat')
    data = sio.loadmat(name)
    return data


# same as save/load in matlab, using package "pickle"
def save_obj(name, data):
    pickle.dump(data, open(name, "wb"))

def load_obj(name, encoding="ASCII"):
    return pickle.load(open(name, "rb"), encoding=encoding)


# read/save strings line by line in text file.
def load_txt(name):
    with open(name) as f:
        lines = f.readlines()
    lines = [x.strip() for x in lines]
    return lines
