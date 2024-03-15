import json

with open('eve.json', 'r') as file:
    # Read each line and process it as JSON
    for line in file:
        # Load the JSON data from the line
        data = json.loads(line)
        
        # Print the data
        print("\n=======================================================================\n")
        print(json.dumps(data, indent=4))