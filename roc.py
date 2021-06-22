'''
John Carter
Created: 2021/05/28 15:12:26
Last modified: 2021/06/14 15:57:13
Create ROC curves for data showing different window sizes
https://scikit-learn.org/stable/auto_examples/model_selection/plot_roc_crossval.html
'''

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import argparse
import glob
import os

import pca

from sklearn.model_selection import StratifiedKFold  
from sklearn import svm
from sklearn.metrics import auc, plot_roc_curve

INFO = '[\u001b[32mINFO\u001b[0m] '
DATA_TYPES = ["syscalls", "packets", "merged"]

def standardize(df, is_mal=0):
    X = df.values
    X = (X - X.mean())/X.std()
    labels = pd.DataFrame(data=len(X)*[is_mal])
    return X, labels

def plot_roc(benign_data_path, malware_data_path, window, filename, malware):
    benign_data = pd.read_csv(benign_data_path)        
    malware_data = pd.read_csv(malware_data_path)
    
    # Standardize the data and assign labels
    benign_data, benign_labels = standardize(benign_data)
    malware_data, malware_labels = standardize(malware_data, 1)

    num_benign_components = pca.get_components(benign_data, window, filename)
    num_malware_components = pca.get_components(malware_data, window, filename)
    n_components = max(num_benign_components, num_malware_components)
    benign_components = pca.pca(benign_data, benign_labels, n_components)
    malware_components = pca.pca(malware_data, malware_labels, n_components)

    # merge benign and malware data, and split into features and labels
    merged = np.concatenate((benign_components, malware_components), axis=0)
    X = merged[:,:-1]
    y = merged[:, -1]

    n_samples, n_features = X.shape

    # Add noisy features
    random_state = np.random.RandomState(0)
    X = np.c_[X, random_state.randn(n_samples, 200 * n_features)]

    # Run classifier with cross-validation and plot ROC curves
    cv = StratifiedKFold(n_splits=6)
    classifier = svm.SVC(kernel='rbf', probability=True,
                        random_state=random_state)

    tprs = []
    aucs = []
    mean_fpr = np.linspace(0, 1, 100)

    fig, ax = plt.subplots()
    for i, (train, test) in enumerate(cv.split(X, y)):
        classifier.fit(X[train], y[train].ravel())
        viz = plot_roc_curve(classifier, X[test], y[test],
                            name='ROC fold {}'.format(i),
                            alpha=0.3, lw=1, ax=ax)
        interp_tpr = np.interp(mean_fpr, viz.fpr, viz.tpr)
        interp_tpr[0] = 0.0
        tprs.append(interp_tpr)
        aucs.append(viz.roc_auc)

    ax.plot([0, 1], [0, 1], linestyle='--', lw=2, color='r',
            label='Chance', alpha=.8)

    mean_tpr = np.mean(tprs, axis=0)
    mean_tpr[-1] = 1.0
    mean_auc = auc(mean_fpr, mean_tpr)
    std_auc = np.std(aucs)
    ax.plot(mean_fpr, mean_tpr, color='b',
            label=r'Mean ROC (AUC = %0.2f $\pm$ %0.2f)' % (mean_auc, std_auc),
            lw=2, alpha=.8)

    print(INFO + f"{malware_data_path} - Mean AUC: {mean_auc}")
    
    std_tpr = np.std(tprs, axis=0)
    tprs_upper = np.minimum(mean_tpr + std_tpr, 1)
    tprs_lower = np.maximum(mean_tpr - std_tpr, 0)
    ax.fill_between(mean_fpr, tprs_lower, tprs_upper, color='grey', alpha=.2,
                    label=r'$\pm$ 1 std. dev.')

    data_name = filename.split(".")[0]
    ax.set(xlim=[-0.05, 1.05], ylim=[-0.05, 1.05],
        title=f"SVM ROC Cross Validation - {data_name} data {window} grouping")
    ax.legend(loc="lower right")

    # create directory if not already created
    if not os.path.exists(f"figures/roc/{window}/{malware}"):
        os.makedirs(f"figures/roc/{window}/{malware}")
        print(INFO + f"Created directory figures/roc/{window}/{malware}\u001b[0m")

    plt.savefig(f'figures/roc/{window}/{malware}/{filename}')
    #print(INFO + f"ROC figure saved to figures/roc/{window}/{malware}/{filename}")
    plt.close('all')

def roc(data_type, malware):
    '''
    Plot ROC curves using cross validation
    Note: this function does all the time directories when 
    called from the SVM code
    '''
    # Read in the data from the file paths passed in, and sort in increasing time window order
    time_grouped_dirs = glob.glob("processed_data/*")
    time_grouped_dirs.sort(key=lambda x: int(x.split("/")[1].strip("s")))

    for dir in time_grouped_dirs:
        window = dir.split("/")[1]
        b_file = dir + f"/{data_type}_benign.csv"

        # Loop through each type of file for the specified malware
        malware_files = glob.glob(f"processed_data/{window}/{data_type}_{malware}*")
        for m_file in malware_files:
            filename = m_file.split("/")[2].split(".")[0] + ".png"
            plot_roc(b_file, m_file, window, filename, malware)

    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Plot ROC curve for a malware and data type")
    parser.add_argument(
        "malware", type=str, default=None, help="Type of malware (keylogger, cryptominer, etc.)"
    )
    parser.add_argument(
        "data_type", type=str, default=None, choices=DATA_TYPES,
        help="Type of the data (syscalls, packets, or merged)"
    )
    
    args = parser.parse_args()
    roc(args.data_type, args.malware)