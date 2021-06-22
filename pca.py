'''
John Carter
Created: 2021/06/04 12:00:20
Last modified: 2021/06/13 20:28:28
Perform Principal Component Analysis on passed in data
https://stackoverflow.com/questions/50796024/feature-variable-importance-after-a-pca-analysis
https://www.mikulskibartosz.name/pca-how-to-choose-the-number-of-components/
https://jakevdp.github.io/PythonDataScienceHandbook/05.09-principal-component-analysis.html
'''

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.decomposition import PCA 
import argparse
import os

INFO = '[\u001b[32mINFO\u001b[0m] '

def get_components(df, window_size, filename=None, plot=False):
    '''
    Plot and return the number of principal components
    necessary to explain 95% of the variance
    '''

    if plot:
        # create directory for this window size if necessary
        if not os.path.exists("figures/pca/" + window_size):
            os.makedirs("figures/pca/" + window_size)
            print(INFO + "Created directory {}\u001b[0m".format("figures/pca/" + window_size))

        # Plot a graph showing the number of necessary components
        pca = PCA().fit(df.data)
        fig, ax = plt.subplots()
        xi = np.arange(1, 6, step=1)
        y = np.cumsum(pca.explained_variance_ratio_[:5])

        plt.ylim(0.0,1.1)
        plt.plot(xi, y, marker='o', linestyle='--', color='b')

        plt.xlabel('Number of Components')
        plt.xticks(np.arange(0, 5, step=1))
        plt.ylabel('Cumulative variance (%)')
        plt.title('Number of Components Needed to Explain Variance')

        plt.axhline(y=0.95, color='r', linestyle='-')
        plt.text(2.5, 0.85, '95% explained variance', color='red', fontsize=10)

        ax.grid(axis='x')
        plt.savefig('figures/pca/%s' % filename)
        print(INFO + "PCA figure saved to figures/pca/%s" % filename)
        plt.close('all')
    
    # Return number of necessary components
    pca = PCA(n_components=0.95)
    _ = pca.fit_transform(df)

    return pca.components_.shape[0]

def pca(df, labels, n_components):
    pca = PCA(n_components=n_components)
    principalComponents = pca.fit_transform(df)
    '''
    # Get the names of the most important features
    most_important = [np.abs(pca.components_[i]).argmax() for i in range(pca.components_.shape[0])]
    feature_names = ['{}'.format(df.columns[i]) for i in range(len(df.columns))]
    important_names = [feature_names[most_important[i]] for i in range(pca.components_.shape[0])]
    dic = {'pc{}'.format(i+1): important_names[i] for i in range(pca.components_.shape[0])}
    names = pd.DataFrame(sorted(dic.items()))
    '''
    columns = ['pc {}'.format(x) for x in range(n_components)]
    principal_components_df = pd.DataFrame(data=principalComponents, columns=columns)
    
    return pd.concat([principal_components_df, labels], axis=1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Perform PCA")
    parser.add_argument(
        "dataframe", type=pd.DataFrame, default=None, help="Input data"
    )
    parser.add_argument(
        "labels", type=pd.DataFrame, default=None, help="Input data"
    )
    parser.add_argument(
        "--n_components", type=int, default=2, help="# of components"
    )

    args = parser.parse_args()
    pca(args.df, args.labels, args.n_components)