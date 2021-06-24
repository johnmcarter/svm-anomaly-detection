'''
John Carter
Created: 2021/04/27 08:54:53
Last modified: 2021/06/24 10:57:26
Analyze system calls and network traffic data using a One-Class SVM
'''

import numpy as np  
import pandas as pd 
pd.set_option("display.precision", 10)
import matplotlib.pyplot as plt
import matplotlib.font_manager
from sklearn.model_selection import train_test_split  
from sklearn import svm
import argparse
import os

import roc
import pca
import metrics

INFO = '[\u001b[32mINFO\u001b[0m] '


def standardize(df, is_mal=0):
    X = df.values
    X = (X - X.mean())/X.std()
    labels = pd.DataFrame(data=len(X)*[is_mal])
    return X, labels

def my_svm(benign_data, malware_data, split, filename, data_type, malware, window, n_components):
    # https://scikit-learn.org/stable/auto_examples/svm/plot_oneclass.html
    
    # Divide benign data into training and testing sets using first two columns 
    # Last column is the labels (0 or 1)
    X_train, X_test = train_test_split(benign_data.values[:,:n_components], test_size=split)
    X_outliers = malware_data.values[:,:n_components]
    
    #roc.roc(data_type, malware)
    #metrics.f1(benign_data, malware_data)

    # Train the one class SVM
    clf = svm.OneClassSVM(nu=0.1, kernel="rbf", gamma=0.1)
    clf.fit(X_train)

    # Make predictions - returns +1 or -1 to indicate whether the data 
    # is an "inlier" or "outlier" respectively
    y_pred_train = clf.predict(X_train)
    y_pred_test = clf.predict(X_test)
    y_pred_outliers = clf.predict(X_outliers)

    n_error_train = y_pred_train[y_pred_train == -1].size
    n_error_test = y_pred_test[y_pred_test == -1].size
    n_error_outliers = y_pred_outliers[y_pred_outliers == 1].size

    print("Malware detection rate: ", ((X_outliers.size-n_error_outliers)/X_outliers.size)*100)
    
    plt.figure(figsize=(10,6))

    # plot the line, the points, and the nearest vectors to the plane
    x_min = min(benign_data.values[:,:2].min(), (X_outliers[:, 0]).min()) - 5
    x_max = max(benign_data.values[:,:2].max(), (X_outliers[:, 0]).max()) + 5
    xx, yy = np.meshgrid(np.linspace(x_min, x_max, 500), np.linspace(x_min, x_max, 500))
    
    Z = clf.decision_function(np.c_[xx.ravel(), yy.ravel()])
    Z = Z.reshape(xx.shape)
    print(Z)

    plt.title("Pi-Router Novelty Detection - {} {} data {} grouping".format(data_type, malware, window))
    plt.contourf(xx, yy, Z, levels=np.linspace(Z.min(), 0, 7), cmap='PuBu')
    a = plt.contour(xx, yy, Z, levels=[0], linewidths=2, colors='darkred')
    plt.contourf(xx, yy, Z, levels=[0, Z.max()], colors='palevioletred')
    
    s=40
    b1 = plt.scatter(X_train[:, 0], X_train[:, 1], c='white', s=s, edgecolors='k')
    b2 = plt.scatter(X_test[:, 0], X_test[:, 1], c='blueviolet', s=s, edgecolors='k')
    b3 = plt.scatter(X_outliers[:, 0], X_outliers[:, 1], c='gold', s=s, edgecolors='k')
    
    plt.axis('tight')

    plt.xlim((x_min, x_max))
    plt.ylim((x_min, x_max))
    plt.legend([a.collections[0], b1, b2, b3],
            ["learned frontier", "training observations",
                "new regular observations", "new abnormal observations"],
            loc="upper left",
            prop=matplotlib.font_manager.FontProperties(size=11))

    plt.xlabel("First Principal Component\nerror train: %d/%d ; errors novel regular: %d/%d ; " \
        "errors novel abnormal: %d/%d ; Malware detection rate: %d/%d"
    % (n_error_train, X_train.size, n_error_test, X_test.size, n_error_outliers, X_outliers.size, \
        X_outliers.size - n_error_outliers, X_outliers.size))
    plt.ylabel("Second Principal Component")

    plt.savefig('figures/classification/%s' % filename)
    print(INFO + "SVM figure saved to figures/classification/%s" % filename)
    plt.close('all')

    
def main(benign_data_path, malware_data_path, split, 
        filename, data_type, malware, n_components=None):
        
    if filename == None:
        filename = "{}_{}.png".format(data_type, malware)
        print(INFO + "No graph filename provided: Using default: ", filename)

    if split == None:
        split = 0.33
        print(INFO + "No train/test split size provided: Using default: ", split)

    # create directory for this window size if necessary
    window_size = benign_data_path.split("/")[1]
    if not os.path.exists("figures/classification/" + window_size):
        os.makedirs("figures/classification/" + window_size)
        print(INFO + "Created directory {}\u001b[0m".format("figures/classification/" + window_size))
    
    # Read in the data from the file paths passed in
    benign_data = pd.read_csv(benign_data_path)
    #print("Benign data\n", benign_data)
    malware_data = pd.read_csv(malware_data_path)
    #print("Malware data\n", malware_data)
    
    # Standardize the data and assign labels
    benign_data, benign_labels = standardize(benign_data)
    malware_data, malware_labels = standardize(malware_data, 1)

    # Get optimum number of principal components by taking max
    if n_components == None:
        num_benign_components = pca.get_components(benign_data, window_size, filename)
        num_malware_components = pca.get_components(malware_data, window_size, filename)
        n_components = max(num_benign_components, num_malware_components)
        print(INFO + f"{n_components} components needed to explain 95% of variance")
    
    # Run PCA on the data prior to feeding it to the SVM
    benign_components = pca.pca(benign_data, benign_labels, n_components)
    malware_components = pca.pca(malware_data, malware_labels, n_components)

    my_svm(benign_components, malware_components, split, filename, 
        data_type, malware, window_size, n_components)
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Classify data using a one-class SVM")
    parser.add_argument(
        "benign_data", type=str, default=None, help="File path to find benign data"
    )
    parser.add_argument(
        "malware_data", type=str, default=None, help="File path to find malware data"
    )
    parser.add_argument(
        "data_type", type=str, default="merged", choices=["syscalls", "packets", "merged"],
        help="Type of the data (syscalls, packets, or merged)"
    )
    parser.add_argument(
        "malware", type=str, default="keylogger", help="Type of malware (keylogger, cryptominer, etc.)"
    )
    parser.add_argument(
        "--split", type=float, default=None, help="Size of testing set"
    )
    parser.add_argument(
        "--graph", type=str, default=None, help="Where to save the results graph"
    )
    parser.add_argument(
        "--n_components", type=int, default=None, help="Number of principal components to use"
    )
    
    args = parser.parse_args()
    main(args.benign_data, args.malware_data, args.split, 
        args.graph, args.data_type, args.malware, args.n_components)