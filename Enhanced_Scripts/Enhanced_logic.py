import pandas as pd
import os
import re
import csv
from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException

def read_vertices_csv(filename):
    df_vertices = pd.read_csv(filename, header=None)
    vertices = {}
    for index, row in df_vertices.iterrows():
        node_number = int(row[0])
        description = row[1]
        node_type = row[2]
        probability = float(row[3])
        vertices[node_number] = {
            "description": description,
            "type": node_type,
            "probability": probability,
            "neighbors": []
        }
    return vertices ,df_vertices

def read_arcs_csv(filename, vertices):
    df_arcs = pd.read_csv(filename, header=None)
    for index, row in df_arcs.iterrows():
        from_node = int(row[0])
        to_node = int(row[1])
        if to_node in vertices:
            vertices[to_node]["neighbors"].append(from_node)
        else:
            print(f"Warning: Node {to_node} not found in VERTICES.CSV")
    return df_arcs

def dfs(node, path, path_prob, paths_to_1, paths_to_30, visited, vertices):
    # Function for depth-first search (same as before)
    if node not in vertices:
        print(f"Warning: Node {node} referenced in ARCS.CSV but not found in VERTICES.CSV")
        return
    path.append(node)
    if vertices[node]["type"] == "AND":
        path_prob *= vertices[node]["probability"]
    visited.add(node)
    if node in {1, 30}:
        if node == 1:
            paths_to_1.append((list(path), path_prob))
        else:
            paths_to_30.append((list(path), path_prob))
    else:
        for neighbor in vertices[node]["neighbors"]:
            if neighbor not in visited:
                dfs(neighbor, path, path_prob, paths_to_1, paths_to_30, visited,vertices)
    path.pop()
    visited.remove(node)
    if vertices[node]["type"] == "AND":
        path_prob /= vertices[node]["probability"]

def get_host_cve(path, risk, df_arcs, df_vertices):
    # Function to get host and vulnerabilities of the path (same as before)
    vurn_host = {}
    combined_data = {}

    for node in path:
        for v_node, host in zip(df_arcs[df_arcs.columns[0]], df_arcs[df_arcs.columns[1]]):
            if node == v_node:
                node_type = df_vertices[df_vertices[df_vertices.columns[0]] == host][df_vertices.columns[2]].values[0]
                node_details = df_vertices[df_vertices[df_vertices.columns[0]] == host][df_vertices.columns[1]].values[0]
                if node_type == 'LEAF':
                    ip = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', node_details)
                    cve = re.findall(r"'(CVE[^']*)'", node_details)
                    if ip and cve:
                        vurn_host[ip[0]] = cve[0] if cve else None

    for host, cve_value in vurn_host.items():
        if host in risk:
            combined_data[host] = {
                'vulnerability': cve_value,
                'Type count': risk[host]['Type count'],
                'combined_score': risk[host]['combined_score'],
                'criticality': risk[host]['criticality'],
                'host_name': risk[host]['host_name']
            }


    very_high = []
    high = []
    for key, details in combined_data.items():
      print(f"  IP Address: {key}")
      print(f"  Host name: {details['host_name']}")
      print(f"  Vulnerability: {details['vulnerability']}")
      print(f"  Type count: {details['Type count']}")
      print(f"  Combined Score: {details['combined_score']}")
      print(f"  Criticality: {details['criticality']}")
      print("-" * 50)
      if details['criticality'] =='Very High':
        very_high.append(details['host_name'])
      elif details['criticality'] =='High':
        high.append(details['host_name'])
    
    return [combined_data,very_high,high]

def calculate_cve_score(filename):
    # Function to read the nessusScan CSV and calculate the combined CVE score for each IP address (same as before)
    cve_scores = {}
    with open(filename, 'r') as file:
        reader = csv.reader(file)
        next(reader)  # Skip the header row
        for row in reader:
            cve = row[0]
            score_str = row[1]
            host = row[3].strip()  
            if score_str:  # Check if the score string is not empty
                try:
                    score = float(score_str)
                    if host not in cve_scores:
                        cve_scores[host] = 0.0
                    cve_scores[host] += score
                except ValueError:
                    print(f"Invalid score value '{score_str}' for host '{host}'")

    return cve_scores

def get_severity_scores(filename):
    # Function to read the severity scores from qualysScan CSV (same as before)
    severity_scores = {}
    with open(filename, 'r') as file:
        reader = csv.reader(file)
        next(reader)  # Skip the header row
        for row in reader:
            severity_str = row[5]  # The Severity column is at index 5
            host_ip = row[0].strip()  # Remove leading/trailing spaces from IP
            host_name = row[9].strip()  # Host Name column is at index 9
            vuln_type = row[4].strip()
            if vuln_type == "Practice" and severity_str:  # Check if it's of type Practice and severity string is not empty
                try:
                    score = float(severity_str)
                    if host_ip not in severity_scores:
                        severity_scores[host_ip] = {'score': 0.0, 'host_name': host_name,'Type': len([vuln_type])}
                    severity_scores[host_ip]['score'] += score
                except ValueError:
                    print(f"Invalid severity value '{severity_str}' for IP '{host_ip}' and host name '{host_name}'")

    return severity_scores

def calculate_criticality(combined_score):
    # Function to calculate the criticality based on the combined score (same as before)
    if combined_score < 5:
        return "Low"
    elif combined_score >= 5 and combined_score < 7:
        return "Medium"
    elif combined_score >= 7 and combined_score < 10:
        return "High"
    else:
        return "Very High"

def send_sms_msg(msg, receiver, receiver_name):
    account_sid = 'AC820f37cbaee96e32087e9c466d5eb715'
    auth_token = '0e53c9f93bcf6cd3058ae54e3d72a3c5'
    client = Client(account_sid, auth_token)

    try:
        message = client.messages.create(
            body=msg,
            to=receiver,
            from_="SG Security"
        )
        print(f"Message sent to {receiver_name}: {message.sid}")
    except TwilioRestException as e:
        print(f"Error sending message to {receiver_name}: {e}")

def send_sms(risk):
    It_secuity_officer_phone = "+447447929418"
    system_admin_phone = "+447447929418"
    operator_phone = "+447447929418"
    for ip, details in risk.items():
        #if ((details['host_name'] == 'workstation') | (details['host_name'] == 'workstation') ) & (details['criticality'] == 'Very High') :
        if (details['host_name'] in ['SCADA1','SCADA2','workstation','webserver'] ) & (details['criticality'] in ['Very High']) :
            print('sending sms to IT Security Officers')
            msg = " 🔴🔴🔴 \n \n VERY HIGH LEVEL ALERT: \n \n Dear IT Security Officers \n \n This device (" + details['host_name'] + ") is at "+details['criticality']+" risk of being compromised. \n \n You MUST take an URGENT action IMMEDIATELY. \n \n \n Risk Assessment Team"

            send_sms_msg(msg,It_secuity_officer_phone,'IT Security Officers')
            print('----------------------------------------------------------')

        elif (details['host_name'] in ['SCADA1','SCADA2','workstation','webserver'] ) & (details['criticality'] in ['High']) :
                print('sending sms to System Admin')
                msg = " 🟠🟠🟠 \n \n HIGH LEVEL ALERT: \n \n Dear System Admin \n \n This device (" + details['host_name'] + ") is at "+details['criticality']+" risk of being compromised. \n \n You MUST take an URGENT action ASAP. \n \n \n Risk Assessment Team"
                send_sms_msg(msg,system_admin_phone,'System Admin')
                print('----------------------------------------------------------')

        elif (details['host_name'] in ['SCADA1','SCADA2','workstation','webserver'] ) & (details['criticality'] in ['Medium']) :
                print('sending sms to System Admin')
                msg = " 🟡🟡🟡 \n \n MEDIUM LEVEL ALERT: \n \n Dear System Admin \n \n This device (" + details['host_name'] + ") is at "+details['criticality']+" risk of being compromised. \n \n You you SHOULD take an APPROPRATE action soon. \n \n \n Risk Assessment Team"
                send_sms_msg(msg,system_admin_phone,'System Admin')
                print('----------------------------------------------------------')

        elif (details['host_name'] in ['SCADA1','SCADA2','workstation','webserver'] ) & (details['criticality'] in ['Low']) :
                print('sending sms to System Admin')
                msg = " 🟢🟢🟢 \n \n LOW LEVEL ALERT: \n \n Dear System Admin \n \n This device (" + details['host_name'] + ") is at "+details['criticality']+" risk of being compromised. \n \n You you SHOULD take an APPROPRATE action soon. \n \n Risk Assessment Team"
                send_sms_msg(msg,system_admin_phone,'System Admin')
                print('----------------------------------------------------------')

        elif (details['host_name'] in ['PLC1','PLC2'] ) & (details['criticality'] in ['Very High']) :
                print('sending sms to Operator and IT Security Officers')

                # for operator
                msg = " 🔴🔴🔴 \n \n VERY HIGH LEVEL ALERT: \n \n Dear Operator \n \n This device (" + details['host_name'] + ") is at "+details['criticality']+" risk of being compromised. \n \n You MUST take an URGENT action IMMEDIATELY. \n \n Risk Assessment Team"
                send_sms_msg(msg,operator_phone,'Operator')

                # for IT security Officers
                msg = " 🔴🔴🔴 \n \n VERY HIGH LEVEL ALERT: Dear IT Security Officers \n \n This device (" + details['host_name'] + ") is at "+details['criticality']+" risk of being compromised. \n \n You MUST take an URGENT action IMMEDIATELY. \n \n Risk Assessment Team"
                send_sms_msg(msg,It_secuity_officer_phone,'IT Security Officers')
                print('----------------------------------------------------------')


        elif (details['host_name'] in ['PLC1','PLC2'] ) & (details['criticality'] in ['High']) :
                print('sending sms to Operator and IT Security Officers')

                # for operator
                msg = " 🟠🟠🟠 \n \n HIGH LEVEL ALERT: \n \n Dear Operator \n \n This device (" + details['host_name'] + ") is at "+details['criticality']+" risk of being compromised. \n \n You MUST take an URGENT action ASAP. \n \n \n Risk Assessment Team"
                send_sms_msg(msg,operator_phone,'Operator')

                # for IT security Officers
                msg = " 🟠🟠🟠 \n \n HIGH LEVEL ALERT: \n \n Dear IT Security Officers \n \n This device (" + details['host_name'] + ") is at "+details['criticality']+" risk of being compromised. \n \n You MUST take an URGENT action ASAP. \n \n \n Risk Assessment Team"
                send_sms_msg(msg,It_secuity_officer_phone,'IT Security Officers')
                print('----------------------------------------------------------')


        elif (details['host_name'] in ['PLC1','PLC2'] ) & (details['criticality'] in ['Medium']) :
                print('sending sms to Operator')
                msg = " 🟡🟡🟡 \n \n MEDIUM LEVEL ALERT: \n \n Dear Operator: \n \n This device (" + details['host_name'] + ") is at "+details['criticality']+" risk of being compromised. \n \n You you SHOULD take an APPROPRATE action soon. \n \n \n Risk Assessment Team"
                send_sms_msg(msg,operator_phone,'operator')
                print('----------------------------------------------------------')

        elif (details['host_name'] in ['PLC1','PLC2'] ) & (details['criticality'] in ['Low']) :
                print('sending sms to Operator')
                msg = " 🟢🟢🟢 \n \n LOW LEVEL ALERT: \n \n Dear Operator: \n \n This device (" + details['host_name'] + ") is at "+details['criticality']+" risk of being compromised. \n \n You SHOULD take an APPROPRATE action soon. \n \n \n Risk Assessment Team"
                send_sms_msg(msg,operator_phone,'operator')
                print('----------------------------------------------------------')

def main():
    vertices_path = os.path.join('uploads', 'VERTICES.CSV')
    arcs_path = os.path.join('uploads', 'ARCS.CSV')
    nessusScan_path = os.path.join('uploads', 'cyberlab_nessusScan.csv')
    qualysScan_path = os.path.join('uploads', 'cyberlab_qualysScan.csv')

    vertices, vertices_df = read_vertices_csv(vertices_path)
    arcs=read_arcs_csv(arcs_path,vertices)

    search_value = 'attackerLocated(internet)'
    starting_node = None
    for node_number, node_info in vertices.items():
        if search_value in node_info["description"]:
            starting_node = node_number
            break

    all_paths_to_1 = []
    all_paths_to_30 = []
    dfs(starting_node, [], 1.0, all_paths_to_1, all_paths_to_30, set(), vertices)

    cve_scores = calculate_cve_score(nessusScan_path)
    severity_scores = get_severity_scores(qualysScan_path)

    # Combine cve_scores and severity_scores into the risk dictionary
    severity_scores = {key: (value['score'], value['host_name']) for key, value in severity_scores.items()}

    # Assuming you have called the function and stored its results in `severity_scores`
    severity_scores = get_severity_scores(qualysScan_path)

    # Convert to desired format
    formatted_scores = {key: (value['score'], value['host_name'], value['Type']) for key, value in severity_scores.items()}

    # If you want to reassign to severity_scores:
    severity_scores = formatted_scores


    risk = {}
    # Calculate the combined score (severity) for each IP address
    for host in set(cve_scores.keys()) | set(severity_scores.keys()):
        # Using the first element of the tuple for the score
        severity_score = severity_scores.get(host, (0.0, '', 0))[0]
        
        combined_score = cve_scores.get(host, 0.0) + severity_score
        
        criticality = calculate_criticality(combined_score)
        # Storing the data in the risk dictionary
        risk[host] = {
            'host_name': severity_scores.get(host, (0.0, 'Unknown Hostname', 0))[1],
            'Type count': severity_scores.get(host, (0.0, 'Unknown Hostname', 0))[2],
            'combined_score': combined_score,
            'criticality': criticality
        }
    
    send_sms(risk)

    paths = {}
    for path, prob in all_paths_to_1:
        # Calculate path related data and store in paths dictionary
        print(f"First Attack Path: {path}, Probability: {prob}")
        print('Related Hosts and its vulnerability,combined_score,and criticality')
        criticality = get_host_cve(path, risk,arcs,vertices_df)
        paths[tuple(path)] = {  # Use tuple(path) because lists are not hashable and cannot be dictionary keys
            'very_high_count': len(criticality[1]),
            'very_high_count': len(criticality[1]),
            'high_count': len(criticality[2]),
        }
        print("_" * 340)

    for path, prob in all_paths_to_30:
        # Calculate path related data and store in paths dictionary
        print(f"Second Attack Path: {path}, Probability: {prob}")
        print('Related Hosts and its vulnerability,combined_score,and criticality')
        criticality = get_host_cve(path, risk,arcs,vertices_df)
        paths[tuple(path)] = {  # Use tuple(path) again
            'very_high_count': len(criticality[1]),
            'high_count': len(criticality[2]),
        }
        print("_" * 400)

    most_critical_path = max(paths, key=lambda k: (paths[k]['very_high_count'], paths[k]['high_count']))
    print("Optimal Attack Path was Computed Successfully:", most_critical_path)
    print("Very High Count:", paths[most_critical_path]['very_high_count'])
    print("High Count:", paths[most_critical_path]['high_count'])

if __name__ == "__main__":
    main()
