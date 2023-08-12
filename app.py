from flask import Flask, render_template, request, jsonify
from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException
import pandas as pd
import re
import csv
import os


app = Flask(__name__)

# Function to handle file upload and save the file
def save_uploaded_file(file):
    # Modify this function to save the file to your desired location
    file.save(f"uploads/{file.filename}")
    return file.filename

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in the request'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    filename = save_uploaded_file(file)

    return jsonify({'filename': filename}), 200

# def send_sms_msg(one,two):
#     pass

def send_sms_msg(msg,reciver):
    account_sid = 'AC820f37cbaee96e32087e9c466d5eb715'
    auth_token = '0e53c9f93bcf6cd3058ae54e3d72a3c5'
    client = Client(account_sid, auth_token)

    message = client.messages.create(
        body=msg,
        to= reciver, #"+447389868204",  # Replace with your phone number
        from_="SG Security"  # Replace with your Twilio number
    )

risk = {}

# Route to trigger the SMS sending function
@app.route('/send_sms', methods=['POST'])
def send_sms():
    # Your existing SMS sending function here...
    # Place the function you shared earlier for sending SMS messages based on the risk dictionary.
    for ip, details in risk.items():

        It_secuity_officer_phone = "+447447929418"
        system_admin_phone = "+447447929418"
        operator_phone = "+447447929418"

        #if ((details['host_name'] == 'workstation') | (details['host_name'] == 'workstation') ) & (details['criticality'] == 'Very High') :
        if (details['host_name'] in ['SCADA1','SCADA2','workstation','webserver'] ) & (details['criticality'] in ['Very High']) :
            print('sending sms to IT Security Officers')
            msg = " 🔴🔴🔴 \n \n VERY HIGH LEVEL ALERT: \n \n Dear IT Security Officers \n \n This device (" + details['host_name'] + ") is at "+details['criticality']+" risk of being compromised. \n \n You MUST take an URGENT action IMMEDIATELY. \n \n \n Risk Assessment Team"

            send_sms_msg(msg,It_secuity_officer_phone)
            print('----------------------------------------------------------')

        elif (details['host_name'] in ['SCADA1','SCADA2','workstation','webserver'] ) & (details['criticality'] in ['High']) :
                print('sending sms to System Admin')
                msg = " 🟠🟠🟠 \n \n HIGH LEVEL ALERT: \n \n Dear System Admin \n \n This device (" + details['host_name'] + ") is at "+details['criticality']+" risk of being compromised. \n \n You MUST take an URGENT action ASAP. \n \n \n Risk Assessment Team"
                send_sms_msg(msg,system_admin_phone)
                print('----------------------------------------------------------')

        elif (details['host_name'] in ['SCADA1','SCADA2','workstation','webserver'] ) & (details['criticality'] in ['Medium']) :
                print('sending sms to System Admin')
                msg = " 🟡🟡🟡 \n \n MEDIUM LEVEL ALERT: \n \n Dear System Admin \n \n This device (" + details['host_name'] + ") is at "+details['criticality']+" risk of being compromised. \n \n You you SHOULD take an APPROPRATE action soon. \n \n \n Risk Assessment Team"
                send_sms_msg(msg,system_admin_phone)
                print('----------------------------------------------------------')

        elif (details['host_name'] in ['SCADA1','SCADA2','workstation','webserver'] ) & (details['criticality'] in ['Low']) :
                print('sending sms to System Admin')
                msg = " 🟢🟢🟢 \n \n LOW LEVEL ALERT: \n \n Dear System Admin \n \n This device (" + details['host_name'] + ") is at "+details['criticality']+" risk of being compromised. \n \n You you SHOULD take an APPROPRATE action soon. \n \n Risk Assessment Team"
                send_sms_msg(msg,system_admin_phone)
                print('----------------------------------------------------------')

        elif (details['host_name'] in ['PLC1','PLC2'] ) & (details['criticality'] in ['Very High']) :
                print('sending sms to Operator and IT Security Officers')

                # for operator
                msg = " 🔴🔴🔴 \n \n VERY HIGH LEVEL ALERT: \n \n Dear Operator \n \n This device (" + details['host_name'] + ") is at "+details['criticality']+" risk of being compromised. \n \n You MUST take an URGENT action IMMEDIATELY. \n \n Risk Assessment Team"
                send_sms_msg(msg,operator_phone)

                # for IT security Officers
                msg = " 🔴🔴🔴 \n \n VERY HIGH LEVEL ALERT: Dear IT Security Officers \n \n This device (" + details['host_name'] + ") is at "+details['criticality']+" risk of being compromised. \n \n You MUST take an URGENT action IMMEDIATELY. \n \n Risk Assessment Team"
                send_sms_msg(msg,It_secuity_officer_phone)
                print('----------------------------------------------------------')


        elif (details['host_name'] in ['PLC1','PLC2'] ) & (details['criticality'] in ['High']) :
                print('sending sms to Operator and IT Security Officers')

                # for operator
                msg = " 🟠🟠🟠 \n \n HIGH LEVEL ALERT: \n \n Dear Operator \n \n This device (" + details['host_name'] + ") is at "+details['criticality']+" risk of being compromised. \n \n You MUST take an URGENT action ASAP. \n \n \n Risk Assessment Team"
                send_sms_msg(msg,operator_phone)

                # for IT security Officers
                msg = " 🟠🟠🟠 \n \n HIGH LEVEL ALERT: \n \n Dear IT Security Officers \n \n This device (" + details['host_name'] + ") is at "+details['criticality']+" risk of being compromised. \n \n You MUST take an URGENT action ASAP. \n \n \n Risk Assessment Team"
                send_sms_msg(msg,It_secuity_officer_phone)
                print('----------------------------------------------------------')


        elif (details['host_name'] in ['PLC1','PLC2'] ) & (details['criticality'] in ['Medium']) :
                print('sending sms to Operator')
                msg = " 🟡🟡🟡 \n \n MEDIUM LEVEL ALERT: \n \n Dear Operator: \n \n This device (" + details['host_name'] + ") is at "+details['criticality']+" risk of being compromised. \n \n You you SHOULD take an APPROPRATE action soon. \n \n \n Risk Assessment Team"
                send_sms_msg(msg,operator_phone)
                print('----------------------------------------------------------')

        elif (details['host_name'] in ['PLC1','PLC2'] ) & (details['criticality'] in ['Low']) :
                print('sending sms to Operator')
                msg = " 🟢🟢🟢 \n \n LOW LEVEL ALERT: \n \n Dear Operator: \n \n This device (" + details['host_name'] + ") is at "+details['criticality']+" risk of being compromised. \n \n You SHOULD take an APPROPRATE action soon. \n \n \n Risk Assessment Team"
                send_sms_msg(msg,operator_phone)
                print('----------------------------------------------------------')

    # Return a JSON response to indicate success or failure
    return jsonify({'message': 'SMS messages sent successfully'}), 200



@app.route("/send-email", methods=["POST"])
def send_email():
        # Return a JSON response to indicate success or failure.
    return jsonify({"message": "Email sent successfully"}), 200

@app.route('/next_page')
def next_page():
    # Read VERTICES.CSV file using pandas and store node information
    vertices_path = os.path.join('uploads', 'VERTICES.CSV')
    arcs_path = os.path.join('uploads', 'ARCS.CSV')
    nessusScan_path = os.path.join('uploads', 'cyberlab_nessusScan.csv')
    qualysScan_path = os.path.join('uploads', 'cyberlab_qualysScan.csv')

    df_vertices = pd.read_csv(vertices_path, header=None)
    vertices = {}
    search_value='attackerLocated(internet)'
    starting_node = None
    for index, row in df_vertices.iterrows():
        node_number = int(row[0])
        description = row[1]
        node_type = row[2]
        probability = float(row[3])
        vertices[node_number] = {"description": description, "type": node_type, "probability": probability, "neighbors": []}
        if search_value in row[1]:
                starting_node = row[0]

    # Read ARCS.CSV file using pandas and update neighbor nodes
    df_arcs = pd.read_csv(arcs_path, header=None)
    for index, row in df_arcs.iterrows():
        from_node = int(row[0])
        to_node = int(row[1])
        if to_node in vertices:
            vertices[to_node]["neighbors"].append(from_node)
        else:
            print(f"Warning: Node {to_node} not found in VERTICES.CSV")

    # Function for depth-first search remains the same...
    def dfs(node, path, path_prob, paths_to_1, paths_to_30, visited):
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
                    dfs(neighbor, path, path_prob, paths_to_1, paths_to_30, visited)

        path.pop()
        visited.remove(node)
        if vertices[node]["type"] == "AND":
            path_prob /= vertices[node]["probability"]

    # get host and vulnerabilities of the path:
    def get_host_cve(parth,risk):
        vurn_host = {}
        for node in path:
            for v_node, host in zip(df_arcs[df_arcs.columns[0]], df_arcs[df_arcs.columns[1]]):
                if node == v_node:
                    node_type = df_vertices[df_vertices[df_vertices.columns[0]] == host][df_vertices.columns[2]].values[0]
                    node_details = df_vertices[df_vertices[df_vertices.columns[0]] == host][df_vertices.columns[1]].values[0]
                    if node_type =='LEAF':
                        #print('host', str(host) + ' is connected to '+ node_details)
                        ip = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', node_details)
                        cve = re.findall(r"'(CVE[^']*)'", node_details)
                        if ip and cve:
                            vurn_host[ip[0]] = cve[0] if cve else None
        print(vurn_host)
        return vurn_host


    def get_host_cve(path, risk):
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

    # Calculate all paths from node number starting_node (of type "AND") to OR node number 1 and 30
    all_paths_to_1 = []
    all_paths_to_30 = []
    dfs(starting_node, [], 1.0, all_paths_to_1, all_paths_to_30, set())

    # Function to read the nessusScan CSV and calculate the combined CVE score for each IP address
    def calculate_cve_score(filename):
        cve_scores = {}
        with open(filename, 'r') as file:
            reader = csv.reader(file)
            next(reader)  # Skip the header row
            for row in reader:
                cve = row[0]
                score_str = row[1]
                host_name = row[4].strip()  # Host Name column is at index 9
                host = row[3].strip()
                if score_str:  # Check if the score string is not empty
                    try:
                        score = float(score_str)
                        if host not in cve_scores:
                            cve_scores[host] = {'score': 0.0, 'host_name': host_name}
                        cve_scores[host]['score'] += score
                    except ValueError:
                        print(f"Invalid score value '{score_str}' for host '{host}'")

        return cve_scores

    def get_severity_scores(filename):
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


    # Function to calculate the criticality based on the combined score
    def calculate_criticality(combined_score):
        if combined_score < 5:
            return "Low"
        elif combined_score >= 5 and combined_score < 7:
            return "Medium"
        elif combined_score >= 7 and combined_score < 10:
            return "High"
        else:
            return "Very High"

    # Read and calculate the CVE scores from cyberlab_nessusScan.csv
    cve_scores = calculate_cve_score(nessusScan_path)

    cve_scores = {key: (value['score'], value['host_name']) for key, value in cve_scores.items()}

    # Assuming you have called the function and stored its results in `severity_scores`
    cve_scores = calculate_cve_score(nessusScan_path)

    # Convert to desired format
    formatted_scores = {key: (value['score'], value['host_name']) for key, value in cve_scores.items()}

    # If you want to reassign to severity_scores:
    cve_scores = formatted_scores




    # Read the severity scores from cyberlab_qualysScan.csv
    severity_scores = get_severity_scores(qualysScan_path)


    severity_scores = {key: (value['score'], value['host_name']) for key, value in severity_scores.items()}

    # Assuming you have called the function and stored its results in `severity_scores`
    severity_scores = get_severity_scores(qualysScan_path)

    # Convert to desired format
    formatted_scores = {key: (value['score'], value['host_name'], value['Type']) for key, value in severity_scores.items()}

    # If you want to reassign to severity_scores:
    severity_scores = formatted_scores


    
    # Calculate the combined score (severity) for each IP address
    for host in set(cve_scores.keys()) | set(severity_scores.keys()):
        # Using the first element of the tuple for the score
        severity_score = severity_scores.get(host, (0.0, '', 0))[0]

        combined_score = cve_scores.get(host, 0.0)[0] + severity_score
        criticality = calculate_criticality(combined_score)
        # Storing the data in the risk dictionary
        risk[host] = {
            'host_name': cve_scores.get(host, (0.0, 'Unknown Hostname'))[1],
            'Type count': severity_scores.get(host, (0.0, 'Unknown Hostname', 0))[2],
            'combined_score': combined_score,
            'criticality': criticality
        }
    
    paths = {}

    custom_lst_dict_1=[]
    custom_lst_dict_30=[]
    # Display all possible paths from node number 19 to nodes number 1 and 30 along with their probabilities
    for path, prob in all_paths_to_1:
        print(f"Path to PLC1: {path}, Probability: {prob}")
        print('Related Hosts and its vulnerability,combined_score,and criticality')
        criticality = get_host_cve(path, risk)
        custom_lst_dict_1.append(criticality[0])
        paths[tuple(path)] = {  # Use tuple(path) because lists are not hashable and cannot be dictionary keys
            'very_high_count': len(criticality[1]),
            'very_high_count': len(criticality[1]),
            'high_count': len(criticality[2]),
        }
        print("_" * 340)

    for path, prob in all_paths_to_30:
        print(f"Path to 30: {path}, Probability: {prob}")
        print('Related Hosts and its vulnerability,combined_score,and criticality')
        criticality = get_host_cve(path, risk)
        custom_lst_dict_30.append(criticality[0])
        paths[tuple(path)] = {  # Use tuple(path) again
            'very_high_count': len(criticality[1]),
            'high_count': len(criticality[2]),
        }


    most_critical_path = max(paths, key=lambda k: (paths[k]['very_high_count'], paths[k]['high_count']))
    print("Optimal Attack Path was Computed Successfully:\n", most_critical_path)
    print("Very High Vulnerability Count:", paths[most_critical_path]['very_high_count'])
    print("High Vulnerability Count:", paths[most_critical_path]['high_count'])

    return render_template('next_page.html'
                        ,most_critical_pth=most_critical_path,
                        very_high_count=paths[most_critical_path]['very_high_count'],
                        high_count=paths[most_critical_path]['high_count'],
                        #list
                        itms_1=all_paths_to_1,
                        itms_30=all_paths_to_30, 
                        # dict
                        dtails_1=custom_lst_dict_1,
                        dtails_30=custom_lst_dict_30,
                        # for btn
                        rsk= risk
                        )

if __name__ == '__main__':
    app.run(debug=True)
