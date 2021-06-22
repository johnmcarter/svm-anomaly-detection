'''
John Carter
Created: 2021/06/09 20:36:50
Last modified: 2021/06/14 15:43:45
Get metrics from dataset and plot F1 scores
'''

from sklearn import svm
from sklearn.model_selection import train_test_split, StratifiedKFold  
from sklearn import metrics
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import argparse
import glob

import pca

INFO = '[\u001b[32mINFO\u001b[0m] '
DATA_TYPES = ["syscalls", "packets", "merged"]
SCORES = {}

def plot_f1_scores(malware):
    ticks = np.array([1, 2, 5, 10, 15, 30])

    for name, values in SCORES.items():
        plt.plot(range(len(values)), values, '.-', label=name)
    plt.title(f"F1 Score for SVM Window Sizes - {malware}")
    plt.ylabel("F1 Score")
    plt.xlabel("Window Size (s)")
    plt.xticks(np.arange(ticks.shape[0]), ticks)
    plt.legend()  
    plt.savefig(f'figures/f1/{malware}.png')
    print(INFO + f'F1 figure saved to figures/f1/{malware}.png')
    plt.close('all')

def standardize(df, is_mal=0):
    X = df.values
    X = (X - X.mean())/X.std()
    labels = pd.DataFrame(data=len(X)*[is_mal])
    return X, labels

def f1(benign_data, malware_data, m_file=None):
    # merge benign and malware data, and split into features and labels
    merged = np.concatenate((benign_data, malware_data), axis=0)
    X = merged[:,:-1]
    y = merged[:, -1]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.33)

    # svm classification
    cv = StratifiedKFold(n_splits=4)
    clf = svm.SVC(kernel='rbf', gamma=0.1, C = 1.0)

    clf.fit(X_train, y_train)
    y_predicted = clf.predict(X_test)
    score = metrics.f1_score(y_test, y_predicted)

    filename = m_file.split("/")[2].strip(".csv")
    names = filename.split("_")
    if names[1] == 'keylogger':
        if len(names[2]) > 2:
            name = f'{names[2]}ms exfiltration rate ({names[3]} keypresses)'
        else:
            name = f'{names[2]}s exfiltration rate ({names[3]} keypresses)'
    else:
        if len(names[2]) > 2:
            name = f'{names[2]}ms exfiltration rate'
        else:
            name = f'{names[2]}s exfiltration rate'

    if name not in SCORES:
        SCORES[name] = [score]
    else:
        SCORES[name].append(score)
             
    print(INFO + f"{m_file} - Avg F1-score: {score}")

def get_data_files(data_type, malware):
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
                benign_data = pd.read_csv(b_file)
                malware_data = pd.read_csv(m_file)
                
                # Standardize the data and assign labels
                benign_data, benign_labels = standardize(benign_data)
                malware_data, malware_labels = standardize(malware_data, 1)

                num_benign_components = pca.get_components(benign_data, window)
                num_malware_components = pca.get_components(malware_data, window)
                n_components = max(num_benign_components, num_malware_components)
                #print(INFO + f"{n_components} components needed to explain 95% of variance")
                
                # Run PCA on the data prior to feeding it to the SVM
                benign_components = pca.pca(benign_data, benign_labels, n_components)
                malware_components = pca.pca(malware_data, malware_labels, n_components)
                f1(benign_components, malware_components, m_file)

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
    get_data_files(args.data_type, args.malware)
    plot_f1_scores(args.malware)