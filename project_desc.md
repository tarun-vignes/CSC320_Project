# CSC 320 Malware Scanner
### Created by Joseph DiMartino, Anthony Eccleston, & Tarun Vigneswaran

# Overview
```text
This Feature-Based Malware Detection Engine uses a hybrid approach to classify if a file is 
malicious or benign. First, the project will extract 7 features from the file being scanned 
(file size, entropy, keywords, api calls, mz headers, urls, and network connections). These 
features are converted to a numerical value, every time a Rule gets triggered, the score 
increases. The second part for classifying is the machine learning aspect. Known malicious 
and benign files were used in training a Random Forest classifier and the results of these
weights were saved to a json file. When running the program, the score (0-100) will be 
decided by a combination of these two parts (60% features, 40% ML). The default threshold
for a file to be malicious is a score of 50.
```

# In-depth desc of the ML model
```text
The Machine learning model was trained with 32 known malicious, and 28 benign files. A 
python program (unpack_malicious_zips.py) will take the .zip files of the malware and 
safely unzip them all to be read. Another python file (train_model.py) was used to 
take all the malicious and benign files in their respected directories and train a 
Random Forest Classifier. The results of the model were saved to model_params.json
and from there a few bridge files were created to run the hybrid engine. For better
visuals on the ML model, a python program (visualize_model.py) was created to show 
three different graphs of the results.
```