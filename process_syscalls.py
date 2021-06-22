'''
John Carter
Created: 2021/04/24 22:22:39
Last modified: 2021/06/14 22:02:14
Transform system call data into dataframes to be fed into ML algorithms
'''

import pandas as pd
pd.set_option("display.precision", 10)
import argparse
import os
from sklearn.feature_extraction.text import CountVectorizer
from functools import reduce

def process_syscalls(input_file, output, group, ngram=2):
    data = pd.read_csv(input_file, header=None)  
    data.columns = ['name','pid','time','number']

    # Remove syscalls associated with data collection
    data.drop(data.index[data['name'] == 'syscall-sensor'], inplace=True)
    data.drop(data.index[data['name'] == 'cicflowmeter'], inplace=True)
    data.reset_index(drop=True, inplace=True)

    # divide the data into attributes and labels
    X_sys = data.drop(['name','pid'], axis=1)
    
    # Get the first timestamp in the file
    first_boottime = X_sys.loc[0]['time']   
    file_creation_time = os.path.getmtime(input_file) # Creation time of log file
    X_sys['time'] = file_creation_time + (X_sys['time'] - first_boottime)
    
    # Convert the time from epoch to US/Eastern and make the time the index to sort on
    X_sys['time'] = pd.to_datetime(X_sys['time'], unit='s')

    X_sys = X_sys.set_index('time')
    X_sys.index = X_sys.index.tz_localize('UTC').tz_convert('US/Eastern')
    
    # Create new features from Syscalls and fragment the data
    X_sys['number'] = X_sys['number'].astype(str)
    syscall_grouped = X_sys.groupby(pd.Grouper(level='time', freq=group))

    df_list = []
    t = []
    for name, group in syscall_grouped:
        t.append(name)
        fragment1 = [" ".join(group['number'])]
        vectorizer = CountVectorizer(ngram_range=(ngram, ngram), analyzer='word')
        sparse_matrix1 = vectorizer.fit_transform(fragment1)
        frequencies1 = sum(sparse_matrix1).toarray()[0]
        df = pd.DataFrame(frequencies1, index=vectorizer.get_feature_names(), columns=['frequency'])
        df_list.append(df.reset_index())
        

    df_final = reduce(lambda left,right: pd.merge(left,right,on=['index'], how='outer'), df_list).fillna(0)
    array = df_final.iloc[:,1:].values
    array = array.T
    bigrams = list(df_final['index'])
    df = pd.DataFrame(data=array,columns=bigrams)

    # set the index to time
    t = pd.Index(t)
    df = df.set_index(t)
    
    print(df)
    df.to_csv(output, index=False)
    print("File saved to %s" % output)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Transform syscall data to dataframe and write to CSV")
    parser.add_argument(
        "input", type=str, default=None, help="Input file name"
    )
    parser.add_argument(
        "output", type=str, default=None, help="Output file name"
    )
    parser.add_argument(
        "--group", type=str, default="30s", help="Time interval by which to group system calls"
    )
    parser.add_argument(
        "--ngram", type=int, default=2, help="Number of syscalls to examine at a time (bi-gram, tri-gram etc.)"
    )
    
    args = parser.parse_args()
    process_syscalls(args.input, args.output, args.group, args.ngram)