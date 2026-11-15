from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
from collections import defaultdict
import hashlib
import json

app = Flask(__name__)
CORS(app)

class ForensicEvent:
    def __init__(self, event_id, user, device, activity, timestamp, details=None):
        self.event_id = event_id
        self.user = user
        self.device = device
        self.activity = activity
        self.timestamp = timestamp
        self.details = details or {}
        self.suspicious = False
        self.flags = []

class EvidenceGraph:
    def __init__(self):
        self.nodes = {}
        self.edges = defaultdict(list)
        self.all_events = []

    def add_event(self, event):
        self.nodes[event.event_id] = event
        self.all_events.append(event)

    def add_edge(self, from_id, to_id, cost):
        if from_id in self.nodes and to_id in self.nodes:
            self.edges[from_id].append((to_id, cost))

    def calculate_edge_cost(self, from_event, to_event):
        base_cost = 1.0
        time_diff = (to_event.timestamp - from_event.timestamp).total_seconds() / 3600
        time_penalty = min(time_diff * 0.1, 5.0)
        relationship_penalty = 5.0
        if from_event.user == to_event.user:
            relationship_penalty -= 2.0
        if from_event.device == to_event.device:
            relationship_penalty -= 1.5
        return base_cost + time_penalty + relationship_penalty

graph = EvidenceGraph()
all_events = []

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})

@app.route('/api/load-dataset', methods=['POST'])
def load_dataset():
    global graph, all_events
    graph = EvidenceGraph()
    all_events = []

    dataset = [
        {'id': 'E001', 'user': 'alex', 'device': 'PC01', 'activity': 'Login', 'time': '2024-01-15 08:30:00', 'size_mb': 0},
        {'id': 'E002', 'user': 'alex', 'device': 'PC01', 'activity': 'Accessed confidential file', 'time': '2024-01-15 08:45:00', 'size_mb': 0},
        {'id': 'E003', 'user': 'alex', 'device': 'PC01', 'activity': 'USB Device Connected', 'time': '2024-01-15 09:00:00', 'size_mb': 0},
        {'id': 'E004', 'user': 'alex', 'device': 'PC01', 'activity': 'File copy operation', 'time': '2024-01-15 09:15:00', 'size_mb': 250},
        {'id': 'E005', 'user': 'alex', 'device': 'PC01', 'activity': 'Network transfer', 'time': '2024-01-15 09:30:00', 'size_mb': 245},
        {'id': 'E006', 'user': 'sam', 'device': 'PC02', 'activity': 'Login', 'time': '2024-01-15 07:00:00', 'size_mb': 0},
        {'id': 'E007', 'user': 'sam', 'device': 'PC02', 'activity': 'Email sent', 'time': '2024-01-15 07:30:00', 'size_mb': 5},
        {'id': 'E008', 'user': 'bob', 'device': 'PC03', 'activity': 'Login', 'time': '2024-01-15 22:00:00', 'size_mb': 0},
        {'id': 'E009', 'user': 'bob', 'device': 'PC03', 'activity': 'USB Device Connected', 'time': '2024-01-15 22:15:00', 'size_mb': 0},
        {'id': 'E010', 'user': 'bob', 'device': 'PC03', 'activity': 'File copy operation', 'time': '2024-01-15 22:30:00', 'size_mb': 180},
    ]

    for record in dataset:
        timestamp = datetime.strptime(record['time'], '%Y-%m-%d %H:%M:%S')
        event = ForensicEvent(record['id'], record['user'], record['device'], record['activity'], timestamp, {'size_mb': record['size_mb']})
        graph.add_event(event)
        all_events.append(event)

    sorted_events = sorted(all_events, key=lambda e: e.timestamp)
    for i, from_event in enumerate(sorted_events):
        for to_event in sorted_events[i+1:]:
            time_diff = (to_event.timestamp - from_event.timestamp).total_seconds() / 3600
            if time_diff <= 24:
                if from_event.user == to_event.user or from_event.device == to_event.device:
                    cost = graph.calculate_edge_cost(from_event, to_event)
                    graph.add_edge(from_event.event_id, to_event.event_id, cost)

    dataset_hash = hashlib.sha256(json.dumps(dataset, default=str).encode()).hexdigest()

    return jsonify({
        'success': True,
        'total_events': len(all_events),
        'total_edges': sum(len(edges) for edges in graph.edges.values()),
        'dataset_hash': dataset_hash,
        'events': [{'id': e.event_id, 'user': e.user, 'device': e.device, 'activity': e.activity, 'timestamp': e.timestamp.isoformat(), 'suspicious': e.suspicious, 'flags': e.flags} for e in all_events]
    })

@app.route('/api/events', methods=['GET'])
def get_events():
    return jsonify({'events': [{'id': e.event_id, 'user': e.user, 'device': e.device, 'activity': e.activity, 'timestamp': e.timestamp.isoformat(), 'suspicious': e.suspicious, 'flags': e.flags} for e in all_events]})
