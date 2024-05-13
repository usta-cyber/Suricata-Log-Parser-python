import csv
def write_quic_to_csv( flow_id, source_ip,source_port, destination_ip,destination_port,quic_data):
    headers = list(quic_data.keys())
    headers.extend(["Flow_ID", "Source_IP", "Source_port","Destination_IP","Destination_port"])

    csv_file = 'quic.csv'

    with open(csv_file, 'a', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers)
        if csvfile.tell() == 0:
            writer.writeheader()

        quic_data["Flow_ID"] = flow_id
        quic_data["Source_IP"] = source_ip
        quic_data["Source_port"] = source_port
        quic_data["Destination_IP"] = destination_ip
        quic_data["Destination_port"] = destination_port
        writer.writerow(quic_data)


def write_flow_to_csv( flow_id, source_ip,source_port, destination_ip,destination_port,flow_data):
    headers = list(flow_data.keys())
    headers.extend(["Flow_ID", "Source_IP", "Source_port","Destination_IP","Destination_port"])
    csv_file = 'flow.csv'

    with open(csv_file, 'a', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers)
        if csvfile.tell() == 0:
            writer.writeheader()

        flow_data["Flow_ID"] = flow_id
        flow_data["Source_IP"] = source_ip
        flow_data["Source_port"] = source_port
        flow_data["Destination_IP"] = destination_ip
        flow_data["Destination_port"] = destination_port
        writer.writerow(flow_data)

def write_fileinfo_to_csv( flow_id, source_ip,source_port, destination_ip,destination_port,fileinfo,http):
    if 'http_content_type' not in http:
        http['http_content_type'] = None

    if 'status' not in http:
        http['status'] = None

    fileinfo.update(http)
    headers = list(fileinfo.keys())
    headers.extend(["Flow_ID", "Source_IP", "Source_port","Destination_IP","Destination_port"])

    keys_to_extract = [
        'filename', 'gaps', 'state', 'stored', 'size', 
        'tx_id', 'hostname', 'url', 'http_user_agent', 
        'http_content_type', 'http_method', 'protocol', 
        'status', 'length'
    ]
    
    csv_file = 'fileinfo.csv'

    with open(csv_file, 'a', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers)
        if csvfile.tell() == 0:
            writer.writeheader()
        filtered_dict = {key: fileinfo.get(key, None) for key in keys_to_extract}

        filtered_dict["Flow_ID"] = flow_id
        filtered_dict["Source_IP"] = source_ip
        filtered_dict["Source_port"] = source_port
        filtered_dict["Destination_IP"] = destination_ip
        filtered_dict["Destination_port"] = destination_port

        writer.writerow(filtered_dict)



def write_dns_to_csv( flow_id, source_ip,source_port, destination_ip,destination_port,dns):

    headers=["Flow_ID", "Source_IP", "Source_port","Destination_IP","Destination_port","type","rrname"]
    data={}

    csv_file = 'dns.csv'

    with open(csv_file, 'a', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers)

        if csvfile.tell() == 0:
            writer.writeheader()

        data["Flow_ID"] = flow_id
        data["Source_IP"] = source_ip
        data["Source_port"] = source_port
        data["Destination_IP"] = destination_ip
        data["Destination_port"] = destination_port
        data["type"] = dns.get("type","")
        data["rrname"] = dns.get("rrname","")
        writer.writerow(data)

def write_alert_to_csv( flow_id, source_ip,source_port, destination_ip,destination_port,alert):
    if alert.get('category') !='Misc activity':
        if 'metadata' in alert:
            del alert['metadata']

        headers = list(alert.keys())
        headers.extend(["Flow_ID", "Source_IP", "Source_port","Destination_IP","Destination_port"])

        csv_file = 'alerts.csv'
        with open(csv_file, 'a', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=headers)
            if csvfile.tell() == 0:
                writer.writeheader()

            alert["Flow_ID"] = flow_id
            alert["Source_IP"] = source_ip
            alert["Source_port"] = source_port
            alert["Destination_IP"] = destination_ip
            alert["Destination_port"] = destination_port
            writer.writerow(alert)

def write_http_to_csv(flow_id, source_ip, source_port, destination_ip, destination_port, http):

    headers = ["hostname", "url", "http_user_agent", "http_content_type", "http_method", "protocol", "status", "length",
               "Flow_ID", "Source_IP", "Source_port", "Destination_IP", "Destination_port"]


    for key in http.keys():
        if key not in headers:
            headers.append(key)

    csv_file = 'http.csv'

    if 'http_user_agent' not in http:
        http['http_user_agent'] = None
    if 'http_content_type' not in http:
        http['http_content_type'] = None

    with open(csv_file, 'a', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers)
        if csvfile.tell() == 0:
            writer.writeheader()

        http["Flow_ID"] = flow_id
        http["Source_IP"] = source_ip
        http["Source_port"] = source_port
        http["Destination_IP"] = destination_ip
        http["Destination_port"] = destination_port
        writer.writerow(http)



def write_tls_to_csv( flow_id, source_ip,source_port, destination_ip,destination_port,version,sni):
    headers = ["Flow_ID", "Source_IP", "Source_port","Destination_IP","Destination_port","version","sni"]
    tls={}
    csv_file = 'tls.csv'
    with open(csv_file, 'a', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers)
        if csvfile.tell() == 0:
            writer.writeheader()

        tls["Flow_ID"] = flow_id
        tls["Source_IP"] = source_ip
        tls["Source_port"] = source_port
        tls["Destination_IP"] = destination_ip
        tls["Destination_port"] = destination_port
        tls["version"] = version
        tls["sni"]=sni
        writer.writerow(tls)