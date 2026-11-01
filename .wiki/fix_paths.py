import json

with open('capture-transaction.json') as f:
    data = json.load(f)

# Fix the content_file paths to use WSL format
for write in data['writes']:
    # Convert D:\ClaudeCode\... to /mnt/d/ClaudeCode/...
    win_path = write['content_file']
    wsl_path = win_path.replace('D:\\', '/mnt/d/').replace('\\', '/')
    write['content_file'] = wsl_path

with open('capture-transaction-wsl.json', 'w') as f:
    json.dump(data, f, indent=2)
print('Saved WSL-compatible transaction bundle')