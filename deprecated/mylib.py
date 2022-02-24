import time
import matplotlib.pyplot as plt
import torch

timer = 0
def tic():
    # reset timer
    global timer
    timer = time.time()

def toc():
    global timer
    def get_str(seconds):
        m, s = divmod(seconds, 60)
        m = int(m)
        if m == 0:
            return "elasped time is {} seconds".format(s)
        h, m = divmod(m, 60)
        if h == 0:
            return "elasped time is {}:{}".format(m, s)
        return "elasped time is {}:{}:{}".format(h, m, s)
    cur_time = time.time()
    elasped_time = cur_time - timer
    timer = cur_time

    print(get_str(elasped_time))

def plot_curve(*args):
    for curve in args:
        plt.plot(list(curve))
    plt.show()

def plot_image(image):
    image = torch.tensor(image)
    if len(image.shape) > 2:
        image = torch.squeeze(image)
    plt.imshow(image, cmap='gray')
    plt.show()

def plot_fft(image):
    image = torch.tensor(image)
    if len(image.shape) > 2:
        image = torch.squeeze(image)
    image -= image.min()
    image = torch.log(torch.log(image + 1) + 1)
    plt.imshow(image, cmap='gray')
    plt.show()

def plot_points(points):
    """
    input: matrix, shape: n*2
    """
    points = torch.tensor(points)
    if len(points.shape) > 2:
        points = torch.squeeze(points)
    x = list(points[:, 0])
    y = list(points[:, 1])
    plt.plot(x, y, 'ro')
    plt.show()

def plot_points_3d_slow(points):
    """
    imput: matrix, shape: n*3
    """
    points = torch.tensor(points)
    if len(points.shape) > 2:
        points = torch.squeeze(points)
    from mpl_toolkits.mplot3d import Axes3D
    fig = plt.figure()
    ax = Axes3D(fig)
    ax.scatter(points[:, 0], points[:, 1], points[:, 2])
    plt.show()


def plot_points_3d(points, scale_factor=0.005):
    """
    imput: matrix, shape: n*3
    """
    points = torch.tensor(points)
    if len(points.shape) > 2:
        points = torch.squeeze(points)
    import mayavi.mlab as mlab
    mlab.points3d(points[:, 0], points[:, 1], points[:, 2], scale_factor=scale_factor)
    mlab.show()
