# Probabilistic Lockset Analysis (PLA)

Source release for paper 'Precise Detection of Kernel Data Races with Probabilistic Lockset Analysis' to appear in Oakland Security & Privacy 2023. (Paper pdf [here](https://www.cs.columbia.edu/~gabe/files/oakland2023_pla.pdf)).


## Setup


First create conda environment:
```
conda create --name=pla --python=3.9
conda activate pla
```

Install dependencies:
```
pip install -r requirements.txt
```

Install pla:
```
pip install .
```

## Race Prediction:

Run `scripts/predict_races.py` to run race prediction. A small corpus of traces `data/sample_corpus` is included in the repo for demonstration:
```
python scripts/predict_races.py --cache -j `nproc` data/sample_corpus
```
Race predictions will be written a csv `pred_races.csv`. Each prediction to test includes two inputs, `wp_input` and `other_input` along with both a watchpoint instruction address corresponding to a racing write instruction, a sequence of instruction addresses predicted to race with the watchpoint instruction, and the probability associated with the race based on the sample traces in the corpus.

A larger set of traces that can be used to reproduce the races identified in the paper can be downloaded [here](https://drive.google.com/file/d/1a9Ygf-0-n-hLyesh83113P6UGQvQhZZx/view?usp=sharing).

## Checking Predictions:

Note: we will add download links for the full evaluation corpus and scripts for race checking to the repository soon.

