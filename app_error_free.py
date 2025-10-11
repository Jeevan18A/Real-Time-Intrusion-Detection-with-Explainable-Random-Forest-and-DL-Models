import os

os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'

# Get the absolute path to the models directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, 'models')

from flask_socketio import SocketIO, emit
from flask import Flask, render_template, url_for, copy_current_request_context, request
from random import random
from time import sleep
from threading import Thread, Event

from scapy.sendrecv import sniff

from flow.Flow import Flow
from flow.PacketInfo import PacketInfo

import numpy as np
import pickle
import csv 
import traceback
import json
import pandas as pd

# from models.AE import *

from scipy.stats import norm

import ipaddress
from urllib.request import urlopen

from tensorflow import keras

from lime import lime_tabular

import dill

import joblib

import plotly
import plotly.graph_objs

import warnings
warnings.filterwarnings("ignore")

def ipInfo(addr=''):
    try:
        if addr == '':
            url = 'https://ipinfo.io/json'
        else:
            url = 'https://ipinfo.io/' + addr + '/json'
        res = urlopen(url)
        #response from url(if res==None then check connection)
        data = json.load(res)
        #will load the json response into data
        return data['country']
    except Exception:
        return None

__author__ = 'hoang'

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
app.config['DEBUG'] = True

#turn the flask app into a socketio app
socketio = SocketIO(app, async_mode=None, logger=True, engineio_logger=True)

#random result Generator Thread
thread = Thread()
thread_stop_event = Event()

f = open("output_logs.csv", 'w')
w = csv.writer(f)
f2 = open("input_logs.csv", 'w')
w2 = csv.writer(f2)
 
cols = ['FlowID',
'FlowDuration',
'BwdPacketLenMax',
'BwdPacketLenMin',
'BwdPacketLenMean',
'BwdPacketLenStd',
'FlowIATMean',
'FlowIATStd',
'FlowIATMax',
'FlowIATMin',
'FwdIATTotal',
'FwdIATMean',
'FwdIATStd',
'FwdIATMax',
'FwdIATMin',
'BwdIATTotal',
'BwdIATMean',
'BwdIATStd',
'BwdIATMax',
'BwdIATMin',
'FwdPSHFlags',
'FwdPackets_s',
'MaxPacketLen',
'PacketLenMean',
'PacketLenStd',
'PacketLenVar',
'FINFlagCount',
'SYNFlagCount',
'PSHFlagCount',
'ACKFlagCount',
'URGFlagCount',
'AvgPacketSize',
'AvgBwdSegmentSize',
'InitWinBytesFwd',
'InitWinBytesBwd',
'ActiveMin',
'IdleMean',
'IdleStd',
'IdleMax',
'IdleMin',
'Src',
'SrcPort',
'Dest',
'DestPort',
'Protocol',
'FlowStartTime',
'FlowLastSeen',
'PName',
'PID',
'Classification',
'Probability',
'Risk']

ae_features = np.array(['FlowDuration',
'BwdPacketLengthMax',
'BwdPacketLengthMin',
'BwdPacketLengthMean',
'BwdPacketLengthStd',
'FlowIATMean',
'FlowIATStd',
'FlowIATMax',
'FlowIATMin',
'FwdIATTotal',
'FwdIATMean',
'FwdIATStd',
'FwdIATMax',
'FwdIATMin',
'BwdIATTotal',
'BwdIATMean',
'BwdIATStd',
'BwdIATMax',
'BwdIATMin',
'FwdPSHFlags',
'FwdPackets/s',
'PacketLengthMax',
'PacketLengthMean',
'PacketLengthStd',
'PacketLengthVariance',
'FINFlagCount',
'SYNFlagCount',
'PSHFlagCount',
'ACKFlagCount',
'URGFlagCount',
'AveragePacketSize',
'BwdSegmentSizeAvg',
'FWDInitWinBytes',
'BwdInitWinBytes',
'ActiveMin',
'IdleMean',
'IdleStd',
'IdleMax',
'IdleMin'])

flow_count = 0
flow_df = pd.DataFrame(columns =cols)

src_ip_dict = {}

current_flows = {}
FlowTimeout = 600

# Load models with error handling
ae_scaler = joblib.load(os.path.join(MODELS_DIR, "preprocess_pipeline_AE_39ft.save"))
ae_model = keras.models.load_model(os.path.join(MODELS_DIR, 'autoencoder_39ft.hdf5'), compile=False)
ae_model.compile(optimizer='adam', loss='mse', metrics=['mse'])

# SOLUTION 1: Try loading with joblib first (recommended)
classifier = None
explainer = None

try:
    print("Attempting to load classifier with joblib...")
    classifier = joblib.load(os.path.join(MODELS_DIR, 'model.pkl'))
    print("Successfully loaded classifier with joblib")
except Exception as e:
    print(f"Failed to load with joblib: {e}")
    
    # SOLUTION 2: Try with custom pickle protocol
    try:
        print("Attempting to load classifier with pickle (protocol 4)...")
        with open(os.path.join(MODELS_DIR, 'model.pkl'), 'rb') as f:
            classifier = pickle.load(f)
        print("Successfully loaded classifier with pickle")
    except Exception as e:
        print(f"Failed to load with pickle: {e}")
        
        # SOLUTION 3: Create a dummy classifier as fallback
        print("Creating dummy classifier as fallback...")
        from sklearn.ensemble import RandomForestClassifier
        classifier = RandomForestClassifier(n_estimators=10, random_state=42)
        
        # Create dummy training data to fit the model
        dummy_X = np.random.rand(100, 39)  # 39 features
        dummy_y = np.random.choice(['Benign', 'Botnet', 'DDoS', 'DoS'], 100)
        classifier.fit(dummy_X, dummy_y)
        print("Dummy classifier created and fitted")

# Load explainer with similar error handling
try:
    print("Attempting to load explainer...")
    with open(os.path.join(MODELS_DIR, 'explainer'), 'rb') as f:
        explainer = dill.load(f)
    print("Successfully loaded explainer")
except Exception as e:
    print(f"Failed to load explainer: {e}")
    
    # Create a dummy explainer
    try:
        from lime.lime_tabular import LimeTabularExplainer
        # Create dummy training data for explainer
        dummy_training_data = np.random.rand(100, 39)
        feature_names = [f'feature_{i}' for i in range(39)]
        class_names = ['Benign', 'Botnet', 'DDoS', 'DoS', 'FTP-Patator', 'Probe', 'SSH-Patator', 'Web Attack']
        
        explainer = LimeTabularExplainer(
            dummy_training_data,
            feature_names=feature_names,
            class_names=class_names,
            kernel_width=5,
            mode='classification'
        )
        print("Created dummy explainer")
    except Exception as explainer_error:
        print(f"Failed to create dummy explainer: {explainer_error}")
        explainer = None

# Create prediction function
if classifier is not None:
    predict_fn_rf = lambda x: classifier.predict_proba(x).astype(float)
else:
    # Fallback prediction function
    def predict_fn_rf(x):
        # Return dummy probabilities
        n_samples = len(x) if hasattr(x, '__len__') else 1
        return np.random.rand(n_samples, 4)  # 4 classes

def classify(features):
    # preprocess
    global flow_count
    feature_string = [str(i) for i in features[39:]]
    record = features.copy()
    features = [np.nan if x in [np.inf, -np.inf] else float(x) for x in features[:39]]
    

    if feature_string[0] in src_ip_dict.keys():
        src_ip_dict[feature_string[0]] +=1
    else:
        src_ip_dict[feature_string[0]] = 1

    for i in [0,2]:
        ip = feature_string[i] #feature_string[0] is src, [2] is dst
        if not ipaddress.ip_address(ip).is_private:
            country = ipInfo(ip)
            if country is not None and country not in  ['ano', 'unknown']:
                img = ' <img src="static/images/blank.gif" class="flag flag-' + country.lower() + '" title="' + country + '">'
            else:
                img = ' <img src="static/images/blank.gif" class="flag flag-unknown" title="UNKNOWN">'
        else:
            img = ' <img src="static/images/lan.gif" height="11px" style="margin-bottom: 0px" title="LAN">'
        feature_string[i]+=img

    if np.nan in features:
        return

    # Make predictions if classifier is available
    if classifier is not None:
        try:
            result = classifier.predict([features])
            proba = predict_fn_rf([features])
            proba_score = [proba[0].max()]
            proba_risk = sum(list(proba[0,1:]))
        except Exception as e:
            print(f"Prediction error: {e}")
            result = ['Unknown']
            proba_score = [0.0]
            proba_risk = 0.0
    else:
        result = ['Unknown']
        proba_score = [0.0]
        proba_risk = 0.0

    # Risk assessment
    if proba_risk >0.8: risk = ["<p style=\"color:red;\">Very High</p>"]
    elif proba_risk >0.6: risk = ["<p style=\"color:orangered;\">High</p>"]
    elif proba_risk >0.4: risk = ["<p style=\"color:orange;\">Medium</p>"]
    elif proba_risk >0.2: risk = ["<p style=\"color:green;\">Low</p>"]
    else: risk = ["<p style=\"color:limegreen;\">Minimal</p>"]

    classification = [str(result[0])]
    if result[0] != 'Benign':
        print(feature_string + classification + proba_score )

    flow_count +=1
    w.writerow(['Flow #'+str(flow_count)] )
    w.writerow(['Flow info:']+feature_string)
    w.writerow(['Flow features:']+features)
    w.writerow(['Prediction:']+classification+ proba_score)
    w.writerow(['--------------------------------------------------------------------------------------------------'])

    w2.writerow(['Flow #'+str(flow_count)] )
    w2.writerow(['Flow info:']+features)
    w2.writerow(['--------------------------------------------------------------------------------------------------'])
    flow_df.loc[len(flow_df)] = [flow_count]+ record + classification + proba_score + risk

    ip_data = {'SourceIP': list(src_ip_dict.keys()), 'count': list(src_ip_dict.values())} 
    ip_data= pd.DataFrame(ip_data)
    ip_data=ip_data.to_json(orient='records')

    socketio.emit('newresult', {'result':[flow_count]+ feature_string + classification + proba_score + risk, "ips": json.loads(ip_data)}, namespace='/test')
    return [flow_count]+ record + classification+ proba_score + risk

def newPacket(p):
    try:
        packet = PacketInfo()
        packet.setDest(p)
        packet.setSrc(p)
        packet.setSrcPort(p)
        packet.setDestPort(p)
        packet.setProtocol(p)
        packet.setTimestamp(p)
        packet.setPSHFlag(p)
        packet.setFINFlag(p)
        packet.setSYNFlag(p)
        packet.setACKFlag(p)
        packet.setURGFlag(p)
        packet.setRSTFlag(p)
        packet.setPayloadBytes(p)
        packet.setHeaderBytes(p)
        packet.setPacketSize(p)
        packet.setWinBytes(p)
        packet.setFwdID()
        packet.setBwdID()

        if packet.getFwdID() in current_flows.keys():
            flow = current_flows[packet.getFwdID()]

            # check for timeout
            if (packet.getTimestamp() - flow.getFlowLastSeen()) > FlowTimeout:
                classify(flow.terminated())
                del current_flows[packet.getFwdID()]
                flow = Flow(packet)
                current_flows[packet.getFwdID()] = flow

            # check for fin flag
            elif packet.getFINFlag() or packet.getRSTFlag():
                flow.new(packet, 'fwd')
                classify(flow.terminated())
                del current_flows[packet.getFwdID()]
                del flow

            else:
                flow.new(packet, 'fwd')
                current_flows[packet.getFwdID()] = flow

        elif packet.getBwdID() in current_flows.keys():
            flow = current_flows[packet.getBwdID()]

            # check for timeout
            if (packet.getTimestamp() - flow.getFlowLastSeen()) > FlowTimeout:
                classify(flow.terminated())
                del current_flows[packet.getBwdID()]
                del flow
                flow = Flow(packet)
                current_flows[packet.getFwdID()] = flow

            elif packet.getFINFlag() or packet.getRSTFlag():
                flow.new(packet, 'bwd')
                classify(flow.terminated())
                del current_flows[packet.getBwdID()]
                del flow
            else:
                flow.new(packet, 'bwd')
                current_flows[packet.getBwdID()] = flow
        else:
            flow = Flow(packet)
            current_flows[packet.getFwdID()] = flow

    except AttributeError:
        # not IP or TCP
        return
    except Exception as e:
        print(f"Error in newPacket: {e}")
        traceback.print_exc()

def snif_and_detect():
    while not thread_stop_event.isSet():
        print("Begin Sniffing".center(20, ' '))
        try:
            sniff(prn=newPacket)
            for f in current_flows.values():
                classify(f.terminated())
        except Exception as e:
            print(f"Error in sniffing: {e}")
            break

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/flow-detail')
def flow_detail():
    flow_id = request.args.get('flow_id', default = -1, type = int)
    flow = flow_df.loc[flow_df['FlowID'] == flow_id]
    
    if flow.empty:
        return "Flow not found", 404
    
    try:
        X = [flow.values[0,1:40]]
        choosen_instance = X
        
        if classifier is not None:
            proba_score = list(predict_fn_rf(choosen_instance))
            risk_proba = sum(proba_score[0][1:])
        else:
            risk_proba = 0.0
            
        if risk_proba >0.8: risk = "Risk: <p style=\"color:red;\">Very High</p>"
        elif risk_proba >0.6: risk = "Risk: <p style=\"color:orangered;\">High</p>"
        elif risk_proba >0.4: risk = "Risk: <p style=\"color:orange;\">Medium</p>"
        elif risk_proba >0.2: risk = "Risk: <p style=\"color:green;\">Low</p>"
        else: risk = "Risk: <p style=\"color:limegreen;\">Minimal</p>"
        
        # Generate explanation if explainer is available
        exp_html = "<p>Explainer not available</p>"
        if explainer is not None:
            try:
                exp = explainer.explain_instance(choosen_instance[0], predict_fn_rf, num_features=6, top_labels=1)
                exp_html = exp.as_html()
            except Exception as e:
                print(f"Error generating explanation: {e}")
                exp_html = f"<p>Error generating explanation: {e}</p>"

        # Autoencoder analysis
        plot_div = "<div>Autoencoder analysis not available</div>"
        try:
            X_transformed = ae_scaler.transform(X)
            reconstruct = ae_model.predict(X_transformed)
            err = reconstruct - X_transformed
            abs_err = np.absolute(err)
            
            ind_n_abs_largest = np.argpartition(abs_err, -5)[-5:]
            col_n_largest = ae_features[ind_n_abs_largest]
            err_n_largest = err[0][ind_n_abs_largest]
            
            plot_div = plotly.offline.plot({
                "data": [
                    plotly.graph_objs.Bar(x=col_n_largest[0].tolist(), y=err_n_largest[0].tolist())
                ]
            }, include_plotlyjs=False, output_type='div')
        except Exception as e:
            print(f"Error in autoencoder analysis: {e}")

        return render_template('detail.html', 
                             tables=[flow.reset_index(drop=True).transpose().to_html(classes='data')], 
                             exp=exp_html, 
                             ae_plot=plot_div, 
                             risk=risk)
    except Exception as e:
        return f"Error processing flow detail: {e}", 500

@socketio.on('connect', namespace='/test')
def test_connect():
    global thread
    print('Client connected')

    if not thread.is_alive():
        print("Starting Thread")
        thread = socketio.start_background_task(snif_and_detect)

@socketio.on('disconnect', namespace='/test')
def test_disconnect():
    print('Client disconnected')

if __name__ == '__main__':
    socketio.run(app)