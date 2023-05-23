# Probabilistic Lockset Analysis (PLA)

Source release for paper 'Precise Detection of Kernel Data Races with Probabilistic Lockset Analysis' to appear in Oakland Security & Privacy 2023. (Paper pdf [here](https://www.cs.columbia.edu/~gabe/files/oakland2023_pla.pdf).


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

## Usage:

Run `scripts/predict_races.py` to run race prediction.
```
python scripts/predict_races.py --cache -j `nproc` data/sample_corpus
```
