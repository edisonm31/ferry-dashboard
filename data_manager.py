import json, os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')

def load_json(filename, default):
    path = os.path.join(DATA_DIR, filename)
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error loading {path}: {e}")
        return default

def save_json(filename, data):
    path = os.path.join(DATA_DIR, filename)
    os.makedirs(DATA_DIR, exist_ok=True)
    print(f"Writing to: {os.path.abspath(path)}")
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)