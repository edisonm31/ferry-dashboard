from werkzeug.security import generate_password_hash
import json

# Load users
with open('data/users.json', 'r') as f:
    users = json.load(f)

# Hash each password
for u in users:
    original = u['password']
    u['password'] = generate_password_hash(original)
    print(f"{u['username']} → {u['password']}")  # Confirm it's hashed

# Save back to file
with open('data/users.json', 'w') as f:
    json.dump(users, f, indent=2)