import pandas as pd

def preprocess_input(data, preprocessor):
    df = pd.DataFrame([data])
    return preprocessor.transform(df)