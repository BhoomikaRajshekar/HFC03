from datetime import datetime
from flask import Flask, jsonify, render_template, request
from scapy.all import sniff
import pandas as pd
from threading import Thread
import time
import joblib
from scapy.layers.inet import IP, TCP

app = Flask(__name__)

# Initialize the capture and prediction flags
capture_running = False
prediction_running = False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start_capture', methods=['POST'])
def start_capture():
    global capture_running
    global prediction_running

    if not capture_running:
        capture_running = True
        Thread(target=run_capture).start()

    if not prediction_running:
        prediction_running = True
        Thread(target=run_prediction).start()

    return "Capture started."

def run_capture():
    with open('captured_traffic.csv', 'w') as file:
        file.write("Time,Source,Destination,Protocol,Length,Src port,Dest port\n")

    start_time = time.time()
    while time.time() - start_time < 100:
        sniff(prn=packet_callback, count=10000)

def run_prediction():
    time.sleep(10)  # Wait for 10 seconds before starting predictions

    while capture_running:
        time.sleep(5)  # Wait for 5 seconds between predictions
        update_predictions()

def update_predictions():
    # Load the scaler
    scaler = joblib.load('scaler.pkl')

    # Load the captured traffic data
    data = pd.read_csv('captured_traffic.csv')

    # Preprocess the data
    X = data.drop(['Time', 'Source', 'Destination', 'Protocol'], axis=1)
    X = X.select_dtypes(include=['float64', 'int64'])
    
    X_scaled = scaler.transform(X)

    # Load the model
    model = joblib.load('ddos_model.pkl')

    # Make predictions
    predictions = model.predict(X_scaled)

    # Update the data with predictions
    data['prediction'] = predictions

    # Save the updated data
    data.to_csv('predictions.csv', index=False)

    if 1 in predictions:
        print("DDoS detected. Stopping network capture.")
        global capture_running
        capture_running = False
        from IPython.display import display, Javascript
        import pygame

        def alert(message):
            display(Javascript(f'alert("{message}");'))

        def play_alert_sound():
            pygame.mixer.init()
            pygame.mixer.music.load("C:\\Users\\racha\\Downloads\\emergency-alarm-with-reverb-29431.mp3")  # replace with the actual path to your sound file
            pygame.mixer.music.play()

        # Example usage
        alert("Warning: Something went wrong!")
        play_alert_sound()
        

def packet_callback(packet):
    src_ip, dst_ip, src_port, dst_port, packet_len, protocol, timestamp = extract_packet_info(packet)
    if src_ip:
        with open('captured_traffic.csv', 'a') as file:
            file.write(f"{timestamp},{src_ip},{dst_ip},{protocol},{packet_len},{src_port},{dst_port}\n")

def extract_packet_info(packet):
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        protocol = 'tcp'
        packet_len = len(packet)
        timestamp = datetime.now().strftime("%H:%M:%S")
        return src_ip, dst_ip, src_port, dst_port, packet_len, protocol, timestamp
    return None, None, None, None, None, None, None


if __name__ == '__main__':
    app.run(debug=True)
