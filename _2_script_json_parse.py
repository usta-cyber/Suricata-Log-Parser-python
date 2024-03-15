import json
import csv

# Open the JSON file
with open('eve.json', 'r') as file:
    # Initialize a list to store extracted data
    extracted_data = []

    # Read each line and process it as JSON
    for line in file:
        # Load the JSON data from the line
        data = json.loads(line)

        # Extract required fields
        extracted_fields = {
            "timestamp": data.get("timestamp", ""),
            "flow_id": data.get("flow_id", ""),
            "in_iface": data.get("in_iface", ""),
            "event_type": data.get("event_type", ""),
            "src_ip": data.get("src_ip", ""),
            "src_port": data.get("src_port", ""),
            "dest_ip": data.get("dest_ip", ""),
            "dest_port": data.get("dest_port", ""),
            "proto": data.get("proto", ""),
            "pkt_src": data.get("pkt_src", ""),
            "community_id": data.get("community_id", "")
        }

        if data.get("event_type") == "quic":
            quic_data = data.get("quic", {})
            print("\n___________________________QUIC_____________________________\n")
            print(quic_data)
        elif data.get("event_type")=="flow":
            print("\n___________________________FLOW_____________________________\n")
            flow_data = data.get("flow", {})
            print(flow_data)
        elif data.get("event_type")=="anomaly":
            print("\n___________________________Amoamaly_____________________________\n")
            flow_data = data.get("anomaly", {})
            print(flow_data)
        elif data.get("event_type")=="tls":
            print("\n___________________________TLS_____________________________\n")
            flow_data = data.get("tls", {})
            print(flow_data)
        elif data.get("event_type")=="tcp":
            print("\n___________________________TCP_____________________________\n")
            flow_data = data.get("tcp", {})
            print(flow_data)

        # Append the extracted data to the list
        extracted_data.append(extracted_fields)

# Define CSV file name
csv_file = 'extracted_data.csv'

# Define CSV column headers
headers = ["timestamp", "flow_id", "in_iface", "event_type", "src_ip", "src_port", "dest_ip", "dest_port", "proto", "pkt_src", "community_id"]

# Write extracted data to CSV file
with open(csv_file, 'w', newline='') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=headers)

    # Write headers
    writer.writeheader()

    # Write data rows
    writer.writerows(extracted_data)

print("CSV file has been created successfully!")
