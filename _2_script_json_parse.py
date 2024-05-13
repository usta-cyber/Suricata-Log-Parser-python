import json
import csv
import _3_eventTypes_parser as EP
with open('F:\\NDR-Project-Folder\Suricata_Log_parser_python\\eve.json', 'r') as file:
    extracted_data = []

    for line in file:

        data = json.loads(line)

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
            "app_proto":data.get("app_proto",""),
            "pkt_src": data.get("pkt_src", ""),
            "community_id": data.get("community_id", "")
        }

        if data.get("event_type") == "quic":
            quic_data = data.get("quic", {})
            print("\n___________________________QUIC_____________________________\n")
            print(quic_data)
            print(data.get("flow_id"),quic_data.get('version',""),quic_data.get('sni',""),quic_data.get('ja3',{}),quic_data.get('extensions',[]))
           # EP.write_quic_to_csv(data.get("flow_id", ""),data.get("src_ip", ""),data.get("src_port", ""),data.get("dest_ip", ""),data.get("dest_ip", ""),quic_data)
        elif data.get("event_type")=="flow":
            print("\n___________________________FLOW_____________________________\n")
            flow_data = data.get("flow", {})
            EP.write_flow_to_csv(data.get("flow_id", ""),data.get("src_ip", ""),data.get("src_port", ""),data.get("dest_ip", ""),data.get("dest_port", ""),flow_data)
            print(data.get("flow_id"),flow_data)
        elif data.get("event_type")=="anomaly":
            print("\n___________________________Amoamaly_____________________________\n")
            flow_data = data.get("anomaly", {})
            print(data)
        elif data.get("event_type")=="tls":
            print("\n___________________________TLS_____________________________\n")
            tls = data.get("tls", {})
            print(data.get("flow_id"),tls)
            EP.write_tls_to_csv(data.get("flow_id", ""),data.get("src_ip", ""),data.get("src_port", ""),data.get("dest_ip", ""),data.get("dest_ip", ""),tls.get("version",""),tls.get("sni",""))                                                                                                                                                                                                                                                                                                                                                                                              
        elif data.get("event_type")=="http":
            print("\n___________________________http_____________________________\n")
            http = data.get("http", {})
            print(data.get("flow_id"),http)
            EP.write_http_to_csv(data.get("flow_id", ""),data.get("src_ip", ""),data.get("src_port", ""),data.get("dest_ip", ""),data.get("dest_ip", ""),http)
        elif data.get("event_type")=="alert":
            print("\n___________________________alert_____________________________\n")
            alert = data.get("alert", {})
            print(data.get("flow_id"),alert)
            EP.write_alert_to_csv(data.get("flow_id", ""),data.get("src_ip", ""),data.get("src_port", ""),data.get("dest_ip", ""),data.get("dest_port", ""),alert)
        elif data.get("event_type")=="tcp":
            print("\n___________________________tcp_____________________________\n")
            flow_data = data.get("tcp", {})
            print(data.get("flow_id"),flow_data)
        elif data.get("event_type")=="fileinfo":
            print("\n___________________________fileinfo_____________________________\n")
            flow_data = data.get("fileinfo", {})
            print(data.get("flow_id"),flow_data,data.get("http",{}))
            EP.write_fileinfo_to_csv(data.get("flow_id", ""),data.get("src_ip", ""),data.get("src_port", ""),data.get("dest_ip", ""),data.get("dest_ip", ""),flow_data,data.get("http",{}))
        elif data.get("event_type")=="dns":
            print("\n___________________________dns_____________________________\n")
            flow_data = data.get("dns", {})
            print(data.get("flow_id"),flow_data)
            EP.write_dns_to_csv(data.get("flow_id", ""),data.get("src_ip", ""),data.get("src_port", ""),data.get("dest_ip", ""),data.get("dest_ip", ""),data.get("dns",{}))

        extracted_data.append(extracted_fields)

csv_file = 'extracted_data.csv'

headers = ["timestamp", "flow_id", "in_iface", "event_type", "src_ip", "src_port", "dest_ip", "dest_port", "proto","app_proto", "pkt_src", "community_id"]

with open(csv_file, 'w', newline='') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=headers)
    writer.writeheader()
    writer.writerows(extracted_data)

print("CSV file has been created successfully!")
