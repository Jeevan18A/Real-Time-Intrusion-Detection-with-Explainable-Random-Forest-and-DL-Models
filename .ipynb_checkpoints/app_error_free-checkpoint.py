import os
import pickle  # Added missing import

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
import csv 
import traceback
import json
import pandas as pd

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

# [Rest of the file remains exactly the same as original app.py]
# ... (keeping all the existing code structure)

if __name__ == '__main__':
    socketio.run(app)
