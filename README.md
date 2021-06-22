# SVM Anomaly Detection

To install the required dependencies, run
```
pip3 install -r requirements.txt
```

## Data Collection
To run the data collection process, run:
```
sudo ./collect_data.sh <syscall log file> <cicflowmeter csv output file>
```
The contents of the script are discussed below.

### System Calls
System call data is collected using a tool called Heimdall [https://github.com/ronin-zero/heimdall.git]. Each system call executed while Heimdall is running is saved to a user-specified log file containing the system call and other metadata.

### Network Traffic 
Network traffic is recorded by CICFlowMeter [https://pypi.org/project/cicflowmeter], which captures packets and transforms them into features to be fed into ML algorithms. NOTE: The version of cicflowmeter available now has bugs and required some debugging to get working properly.

## Using the Data
### Automated Data Processing
```process_data.py``` automates the data processing stage by taking in a window size argument and an option merge argument and calls the next three scripts to do the heavy lifting of data processing.
```
python3 process_data.py <raw data path> <window size> --merge <True/False>
```

### System Call Processing
```process_syscalls.py``` takes a system call log file as input and transforms it into a pandas dataframe. The usage for this script is:
```
python3 process_syscalls.py <input file path> <output file path> --group <frequency to group syscalls> --ngram <integer to indicate bi-gram, tri-gram etc.>
```

### Network Traffic Processing
```process_packets.py``` takes the output from cicflowmeter as input and transforms it into a pandas dataframe. The usage for this script is:
```
python3 process_packets.py <input file path> <output file path> --group <frequency to group packets>
```

### Merging System Calls and Network Data
```merge.py``` takes input csv files for system call and network traffic data, and merges them into one dataframe saved to a csv file. The usage for this script is:
```
python3 merge.py <syscall file path> <network data file path> <output file path>
```

### Running the Algorithm
To run the SVM using benign and malicious data, run this command from the root directory:
```
python3 svm.py <benign csv file> <malicious csv file> --split <size of testing set expressed as float> --graph <filename for output graph> --text <text to include in output graph title>
```

The script ```run_svm.py``` is provided to further automate the classification process. Its usage is
```
python3 run_svm.py <window size> <type of data (syscalls, packets, merged)> <type of malware>
```

### ROC Curves, F1-scores, and PCA
#### ROC Curves
```roc.py``` creates ROC curves for passed in data using k-folds cross-validation. The usage for this script is:
```
python3 roc.py <malware type> <data type>
```

#### F1-scores
```metrics.py``` creates plots that show F1 scores for running a SVM for different time windows. The usage for this script is below:
```
python3 metrics.py <malware type> <data type>
```

#### PCA
```pca.py``` performs PCA on a Pandas dataframe, and returns the number of principal components specified by the user. The usage for this script is below:
```
python3 pca.py <dataframe> <labels (benign or malware)> <n_components (optional)>
```