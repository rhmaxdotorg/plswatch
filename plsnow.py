#!/usr/bin/env python
#
# PulseChain Now
#
# Flask App for PulseChain Watch in a Web Browser
#
# Usage
# ./plsnow.py
#
# Setup
# - pip install flask
#

import os
import sys
import re
import pty
import time
import atexit
import signal
import logging
import flask
from flask import Flask, render_template, stream_with_context, Response, jsonify
import itertools
from itertools import cycle
from collections import deque
from threading import Thread, Lock, Condition
import subprocess

logging.basicConfig(level=logging.INFO)

# configuration
APP_HOME = '/home/CHANGEME/plswatch' # update for scripts location

PORT = 8080

# cycle through the hex/pls colors for txs
HEX_COLOR = '#d70076'
PLS_COLOR = '#ab20fd'

# global variables
process = None
process_started = False
fd1 = None
data_lock = Lock()
data_condition = Condition()
read_positions = {}
client_counter = itertools.count()
token_counts = {}

# transaction config
MAX_TOKEN = 1000 # note: keep consistent with MAX_LINES on page via JS
stream_data = deque(maxlen=None) # check for running of memory issues
token_history = deque(maxlen=None) # same

plsnow = Flask(__name__)

color_cycle = cycle([HEX_COLOR, PLS_COLOR])

def rotate_color():
    global color_cycle
    return next(color_cycle)

# cleanup plswatch process
def cleanup():
    global process, fd1

    # tired of debugging why the process won't terminate so this is a quick workaround
    try:
        subprocess.run(['pkill', '-f', 'python.*plswatch.py'], check=True)
    except:
        pass

    # if process and process.poll() is None:
    #     #process.terminate()
    #     os.killpg(os.getpgid(process.pid), signal.SIGKILL)
    #     process.wait()

    if fd1 is not None:
        try:
            os.fstat(fd1)
            os.close(fd1)
        except OSError:
            pass

atexit.register(cleanup)

def stop(signum, frame):
    cleanup()
    signal.signal(signal.SIGINT, signal.getsignal(signal.SIGINT))
    print(os.linesep)
    sys.exit(0)

# catch ctrl+c
signal.signal(signal.SIGINT, stop)

def is_valid_token(token):
    try:
        float(token)
        return False
    except ValueError:
        return ',' not in token

# data stream read and count tokens
def read_stream_data():
    global fd1, stream_data, process_started, data_condition, token_counts, token_history

    link_regex = re.compile(r'<a[^>]*>([^<]+)</a>')
    swap_regex = re.compile(r'SWAP\s[\d.]+\s(.*?)\s->\s[\d.]+\s(.*?)\s\[')

    # wait for plswatch to start before reading data
    while not process_started:
        time.sleep(0.1)

    while True:
        try:
            data = os.read(fd1, 4096)
        except Exception as e:
            logging.info('%s' % e)
            pass

        if data:
            decoded_data = data.decode('utf-8', errors='ignore').strip()

        if decoded_data:
            lines = decoded_data.split('\n')

            with data_lock:
                for line in lines:
                    if('->' not in line or ':' not in line):
                        continue

                    # truncate tx hash
                    if('[' in line and ']' in line):
                        start = line.find('[') + 1
                        end = line.find(']', start)

                        hash = line[start:end]

                        match = link_regex.search(hash)

                        if match:
                            link = match.group(0)
                            tx_hash = match.group(1).strip()

                            truncated_hash = tx_hash[:5] + '....' + tx_hash[-4:]
                            truncated_link = link.replace(f'">{tx_hash}<', f'">{truncated_hash}<')

                            line = line[:start] + " " + truncated_link + " " + line[end:]
                            # logging.info('%s' % line)

                    # remove SWAP from line as that is the primary tx type shown
                    display_line = line.replace('SWAP ', '', 1)

                    color = rotate_color()
                    formatted_line = f"<span style='color: {color};'>{display_line}</span>"

                    if(len(stream_data) == stream_data.maxlen):
                        stream_data.popleft()

                    stream_data.append(formatted_line)

                    match = swap_regex.match(line)

                    if match:
                        token1, token2 = match.groups()

                        if(is_valid_token(token1)):
                            token_counts[token1] = token_counts.get(token1, 0) + 1

                        if(is_valid_token(token2)):
                            token_counts[token2] = token_counts.get(token2, 0) + 1

                        token_history.append((token1, token2))

                        if(len(token_history) == MAX_TOKEN):
                            old_token1, old_token2 = token_history.popleft()

                            for old_token in [old_token1, old_token2]:
                                if(token_counts.get(old_token, 0) > 0):
                                    token_counts[old_token] -= 1
                                    if(token_counts[old_token] == 0):
                                        del token_counts[old_token]

                with data_condition:
                    data_condition.notify_all()

        time.sleep(0.1)

stream_thread = Thread(target=read_stream_data)
stream_thread.daemon = True
stream_thread.start()

@plsnow.before_request
def before_request():
    global client_counter
    flask.g.client_id = next(client_counter) # assign unique id to each client

@plsnow.teardown_request
def teardown_request(exception):
    global data_lock

    client_id = flask.g.client_id

    with data_lock:
        read_positions.pop(client_id, None)

# start plswatch from app runs and prior to any requests
@plsnow.before_request
def start_process():
    global process, process_started, fd1

    if not process_started:
        fd1, fd2 = pty.openpty()

        logging.info('Starting plswatch...')

        process = subprocess.Popen(['python',
                                    '-u',
                                    APP_HOME + '/' + 'plswatch.py'],
                                    text=True,
                                    stdout=fd2,
                                    stderr=fd2,
                                    bufsize=1,
                                    preexec_fn=os.setsid)
        os.close(fd2)

        process_started = True

@plsnow.route('/')
def index():
    return render_template('index.html')

# get live stream for real time data from app
@plsnow.route('/stream')
def stream():
    def generate():
        global stream_data, data_lock, data_condition

        last_sent_line_index = -1

        while True:
            with data_condition:
                data_condition.wait(timeout=0.1)

            with data_lock:
                current_stream_size = len(stream_data)

                start_index = max(0, current_stream_size - MAX_TOKEN)

                for i in range(last_sent_line_index + 1, current_stream_size):
                    yield f"event: message\ndata: {stream_data[i]}\n\n"

                last_sent_line_index = current_stream_size - 1

            time.sleep(0.01)

    return Response(stream_with_context(generate()), content_type='text/event-stream')

# token counts
@plsnow.route('/tokens')
def tokens():
    global token_counts
    return jsonify(token_counts)

if(__name__ == '__main__'):
    plsnow.run(port=PORT, threaded=True, debug=False)
