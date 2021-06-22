'''
John Carter
Created: 2021/05/03 18:15:35
Last modified: 2021/05/29 14:34:34
Transform network traffic data into a dataframe to be fed into ML algorithms
'''

import pandas as pd
pd.set_option("display.precision", 10)
import dateutil
import argparse

def process_packets(input_file, output, group):
    data = pd.read_csv(input_file) 

    # Divide the data into attributes and labels
    X_benign = data.drop(['src_ip', 'dst_ip'], axis=1)
    X = X_benign.values 
    
    # Convert date from string to date times and set that to be index of dataframe
    X_benign['timestamp'] = X_benign['timestamp'].apply(dateutil.parser.parse, dayfirst=True)
    X_benign = X_benign.set_index('timestamp')

    # Group Network Data by the timestamp
    df = X_benign.groupby(pd.Grouper(level='timestamp', freq=group)).describe()
    df = df.fillna(0)
    df = df.drop(['count','min','max','std','mean'], axis=1, level=1)
    df.index = df.index.tz_localize('US/Eastern')
    
    # Merge first two header rows
    df.columns = [f'{i}-{j}' for i, j in df.columns]

    print(df)
    df.to_csv(output, index=False)
    print("File saved to %s" % output)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Transform network traffic data to dataframe and write to CSV")
    parser.add_argument(
        "input", type=str, default=None, help="Input file name"
    )
    parser.add_argument(
        "output", type=str, default=None, help="Output file name"
    )
    parser.add_argument(
        "--group", type=str, default="30s", help="Time interval by which to group packets"
    )
    
    args = parser.parse_args()
    process_packets(args.input, args.output, args.group)