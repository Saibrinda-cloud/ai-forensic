from flask import Flask, request, jsonify
from flask_cors import CORS
import hashlib
import json
import time
from datetime import datetime
from collections import deque, defaultdict
import heapq
from typing import List, Dict, Tuple, Optional

app = Flask(__name__)
CORS(app)

# ============================================================================
# DATA STRUCTURES & FORENSIC EVIDENCE MODEL
# ============================================================================

class ForensicEvent:
    """Represents a single evidence event"""
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
    """Directed weighted graph for evidence relationships"""
    def __init__(self):
        self.nodes = {}  # event_id -> ForensicEvent
        self.edges = defaultdict(list)  # event_id -> [(neighbor_id, cost), ...]
        self.all_events = []

    def add_event(self, event: ForensicEvent):
        self.nodes[event.event_id] = event
        self.all_events.append(event)

    def add_edge(self, from_id, to_id, cost):
        """Add weighted edge from from_id to to_id"""
        if from_id in self.nodes and to_id in self.nodes:
            self.edges[from_id].append((to_id, cost))

    def get_neighbors(self, event_id):
        """Get all neighbors of an event"""
        return self.edges.get(event_id, [])

    def calculate_edge_cost(self, from_event: ForensicEvent, to_event: ForensicEvent) -> float:
        """
        Cost function: Cost(e) = 1 + T + R
        T = time-gap penalty
        R = relationship penalty
        """
        base_cost = 1.0
        
        # Time-gap penalty (in hours)
        time_diff = (to_event.timestamp - from_event.timestamp).total_seconds() / 3600
        time_penalty = min(time_diff * 0.1, 5.0)  # Cap at 5.0
        
        # Relationship penalty
        relationship_penalty = 5.0
        
        if from_event.user == to_event.user:
            relationship_penalty -= 2.0
        if from_event.device == to_event.device:
            relationship_penalty -= 1.5
        if from_event.device == to_event.device and from_event.user == to_event.user:
            relationship_penalty -= 1.0
        
        relationship_penalty = max(relationship_penalty, 0.5)
        
        return base_cost + time_penalty + relationship_penalty

# ============================================================================
# SEARCH ALGORITHMS
# ============================================================================

class SearchAlgorithms:
    """Implementation of BFS, DFS, and UCS for evidence investigation"""
    
    @staticmethod
    def bfs(graph: EvidenceGraph, start_id: str, goal_id: str) -> Dict:
        """
        Breadth-First Search
        Explores nodes level by level, finds path with fewest edges
        """
        start_time = time.time()
        visited = set()
        queue = deque([(start_id, [start_id])])
        explored_nodes = 0
        
        while queue:
            current_id, path = queue.popleft()
            explored_nodes += 1
            
            if current_id in visited:
                continue
            visited.add(current_id)
            
            if current_id == goal_id:
                execution_time = time.time() - start_time
                return {
                    'found': True,
                    'path': path,
                    'path_length': len(path) - 1,
                    'total_cost': calculate_path_cost(graph, path),
                    'explored_nodes': explored_nodes,
                    'execution_time': execution_time
                }
            
            for neighbor_id, _ in graph.get_neighbors(current_id):
                if neighbor_id not in visited:
                    queue.append((neighbor_id, path + [neighbor_id]))
        
        execution_time = time.time() - start_time
        return {
            'found': False,
            'path': [],
            'path_length': 0,
            'total_cost': 0,
            'explored_nodes': explored_nodes,
            'execution_time': execution_time
        }

    @staticmethod
    def dfs(graph: EvidenceGraph, start_id: str, goal_id: str) -> Dict:
        """
        Depth-First Search
        Explores one branch deeply before backtracking
        """
        start_time = time.time()
        visited = set()
        stack = [(start_id, [start_id])]
        explored_nodes = 0
        
        while stack:
            current_id, path = stack.pop()
            explored_nodes += 1
            
            if current_id in visited:
                continue
            visited.add(current_id)
            
            if current_id == goal_id:
                execution_time = time.time() - start_time
                return {
                    'found': True,
                    'path': path,
                    'path_length': len(path) - 1,
                    'total_cost': calculate_path_cost(graph, path),
                    'explored_nodes': explored_nodes,
                    'execution_time': execution_time
                }
            
            for neighbor_id, _ in reversed(graph.get_neighbors(current_id)):
                if neighbor_id not in visited:
                    stack.append((neighbor_id, path + [neighbor_id]))
        
        execution_time = time.time() - start_time
        return {
            'found': False,
            'path': [],
            'path_length': 0,
            'total_cost': 0,
            'explored_nodes': explored_nodes,
            'execution_time': execution_time
        }

    @staticmethod
    def ucs(graph: EvidenceGraph, start_id: str, goal_id: str) -> Dict:
        """
        Uniform Cost Search
        Expands the node with lowest accumulated path cost
        Guarantees optimal path for non-negative costs
        """
        start_time = time.time()
        visited = set()
        # Priority queue: (cost, current_id, path)
        priority_queue = [(0, start_id, [start_id])]
        explored_nodes = 0
        
        while priority_queue:
            current_cost, current_id, path = heapq.heappop(priority_queue)
            explored_nodes += 1
            
            if current_id in visited:
                continue
            visited.add(current_id)
            
            if current_id == goal_id:
                execution_time = time.time() - start_time
                return {
                    'found': True,
                    'path': path,
                    'path_length': len(path) - 1,
                    'total_cost': current_cost,
                    'explored_nodes': explored_nodes,
                    'execution_time': execution_time
                }
            
            for neighbor_id, edge_cost in graph.get_neighbors(current_id):
                if neighbor_id not in visited:
                    new_cost = current_cost + edge_cost
                    heapq.heappush(priority_queue, (new_cost, neighbor_id, path + [neighbor_id]))
        
        execution_time = time.time() - start_time
        return {
            'found': False,
            'path': [],
            'path_length': 0,
            'total_cost': 0,
            'explored_nodes': explored_nodes,
            'execution_time': execution_time
        }

# ============================================================================
# SUSPICIOUS ACTIVITY DETECTION
# ============================================================================

class SuspiciousActivityDetector:
    """Detects suspicious patterns in forensic data"""
    
    WORKING_HOURS = (8, 18)  # 8 AM to 6 PM
    
    @staticmethod
    def detect_unusual_login(event: ForensicEvent) -> bool:
        """Check if login is outside working hours"""
        if event.activity.lower() == 'login':
            hour = event.timestamp.hour
            if hour < SuspiciousActivityDetector.WORKING_HOURS[0] or hour > SuspiciousActivityDetector.WORKING_HOURS[1]:
                event.flags.append("Unusual login time")
                event.suspicious = True
                return True
        return False

    @staticmethod
    def detect_usb_connection(event: ForensicEvent) -> bool:
        """Detect USB device connections"""
        if 'usb' in event.activity.lower() or 'removable' in event.activity.lower():
            event.flags.append("Removable device connection")
            event.suspicious = True
            return True
        return False

    @staticmethod
    def detect_file_copy(event: ForensicEvent) -> bool:
        """Detect file copy operations"""
        if 'copy' in event.activity.lower() or 'copy' in str(event.details).lower():
            event.flags.append("File copy operation")
            event.suspicious = True
            return True
        return False

    @staticmethod
    def detect_large_transfer(event: ForensicEvent) -> bool:
        """Detect unusually large transfers"""
        if event.details.get('size_mb', 0) > 100:
            event.flags.append(f"Large transfer: {event.details.get('size_mb')} MB")
            event.suspicious = True
            return True
        return False

    @staticmethod
    def analyze_all_events(events: List[ForensicEvent]) -> List[ForensicEvent]:
        """Run all detection rules"""
        for event in events:
            SuspiciousActivityDetector.detect_unusual_login(event)
            SuspiciousActivityDetector.detect_usb_connection(event)
            SuspiciousActivityDetector.detect_file_copy(event)
            SuspiciousActivityDetector.detect_large_transfer(event)
        return events

# ============================================================================
# GLOBAL STATE
# ============================================================================

graph = EvidenceGraph()
all_events = []

# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.route('/api/load-dataset', methods=['POST'])
def load_dataset():
    """Load sample forensic dataset"""
    global graph, all_events
    
    graph = EvidenceGraph()
    all_events = []
    
    # Sample dataset
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
    
    # Create events
    for record in dataset:
        timestamp = datetime.strptime(record['time'], '%Y-%m-%d %H:%M:%S')
        event = ForensicEvent(
            record['id'],
            record['user'],
            record['device'],
            record['activity'],
            timestamp,
            {'size_mb': record['size_mb']}
        )
        graph.add_event(event)
        all_events.append(event)
    
    # Build graph connections based on rules
    sorted_events = sorted(all_events, key=lambda e: e.timestamp)
    for i, from_event in enumerate(sorted_events):
        for to_event in sorted_events[i+1:]:
            # Check if events should be connected
            time_diff = (to_event.timestamp - from_event.timestamp).total_seconds() / 3600
            if time_diff <= 24:  # Within 24 hours
                if from_event.user == to_event.user or from_event.device == to_event.device:
                    cost = graph.calculate_edge_cost(from_event, to_event)
                    graph.add_edge(from_event.event_id, to_event.event_id, cost)
    
    # Detect suspicious activities
    all_events = SuspiciousActivityDetector.analyze_all_events(all_events)
    
    # Calculate hash
    dataset_hash = hashlib.sha256(json.dumps(dataset, default=str).encode()).hexdigest()
    
    return jsonify({
        'success': True,
        'total_events': len(all_events),
        'total_edges': sum(len(edges) for edges in graph.edges.values()),
        'dataset_hash': dataset_hash,
        'events': [
            {
                'id': e.event_id,
                'user': e.user,
                'device': e.device,
                'activity': e.activity,
                'timestamp': e.timestamp.isoformat(),
                'suspicious': e.suspicious,
                'flags': e.flags
            }
            for e in all_events
        ]
    })

@app.route('/api/events', methods=['GET'])
def get_events():
    """Get all loaded events"""
    return jsonify({
        'events': [
            {
                'id': e.event_id,
                'user': e.user,
                'device': e.device,
                'activity': e.activity,
                'timestamp': e.timestamp.isoformat(),
                'suspicious': e.suspicious,
                'flags': e.flags
            }
            for e in all_events
        ]
    })

@app.route('/api/search', methods=['POST'])
def search():
    """Run search algorithms"""
    data = request.json
    start_id = data.get('start_id')
    goal_id = data.get('goal_id')
    algorithm = data.get('algorithm', 'bfs')
    
    if not graph.nodes:
        return jsonify({'error': 'Dataset not loaded'}), 400
    
    if algorithm == 'bfs':
        result = SearchAlgorithms.bfs(graph, start_id, goal_id)
    elif algorithm == 'dfs':
        result = SearchAlgorithms.dfs(graph, start_id, goal_id)
    elif algorithm == 'ucs':
        result = SearchAlgorithms.ucs(graph, start_id, goal_id)
    else:
        return jsonify({'error': 'Unknown algorithm'}), 400
    
    # Get event details for path
    path_details = []
    if result['found']:
        for event_id in result['path']:
            event = graph.nodes[event_id]
            path_details.append({
                'id': event.event_id,
                'user': event.user,
                'device': event.device,
                'activity': event.activity,
                'timestamp': event.timestamp.isoformat()
            })
    
    return jsonify({
        'algorithm': algorithm,
        'found': result['found'],
        'path': result['path'],
        'path_details': path_details,
        'path_length': result['path_length'],
        'total_cost': round(result['total_cost'], 2),
        'explored_nodes': result['explored_nodes'],
        'execution_time_ms': round(result['execution_time'] * 1000, 2)
    })

@app.route('/api/compare-algorithms', methods=['POST'])
def compare_algorithms():
    """Compare all three algorithms"""
    data = request.json
    start_id = data.get('start_id')
    goal_id = data.get('goal_id')
    
    if not graph.nodes:
        return jsonify({'error': 'Dataset not loaded'}), 400
    
    results = {
        'bfs': SearchAlgorithms.bfs(graph, start_id, goal_id),
        'dfs': SearchAlgorithms.dfs(graph, start_id, goal_id),
        'ucs': SearchAlgorithms.ucs(graph, start_id, goal_id)
    }
    
    return jsonify({
        'comparison': {
            'bfs': {
                'found': results['bfs']['found'],
                'path_length': results['bfs']['path_length'],
                'total_cost': round(results['bfs']['total_cost'], 2),
                'explored_nodes': results['bfs']['explored_nodes'],
                'execution_time_ms': round(results['bfs']['execution_time'] * 1000, 2)
            },
            'dfs': {
                'found': results['dfs']['found'],
                'path_length': results['dfs']['path_length'],
                'total_cost': round(results['dfs']['total_cost'], 2),
                'explored_nodes': results['dfs']['explored_nodes'],
                'execution_time_ms': round(results['dfs']['execution_time'] * 1000, 2)
            },
            'ucs': {
                'found': results['ucs']['found'],
                'path_length': results['ucs']['path_length'],
                'total_cost': round(results['ucs']['total_cost'], 2),
                'explored_nodes': results['ucs']['explored_nodes'],
                'execution_time_ms': round(results['ucs']['execution_time'] * 1000, 2)
            }
        }
    })

@app.route('/api/suspicious-activities', methods=['GET'])
def get_suspicious():
    """Get all suspicious activities"""
    suspicious = [e for e in all_events if e.suspicious]
    return jsonify({
        'suspicious_count': len(suspicious),
        'suspicious_events': [
            {
                'id': e.event_id,
                'user': e.user,
                'device': e.device,
                'activity': e.activity,
                'timestamp': e.timestamp.isoformat(),
                'flags': e.flags
            }
            for e in suspicious
        ]
    })

@app.route('/api/timeline', methods=['GET'])
def get_timeline():
    """Get event timeline sorted by timestamp"""
    sorted_events = sorted(all_events, key=lambda e: e.timestamp)
    return jsonify({
        'timeline': [
            {
                'id': e.event_id,
                'user': e.user,
                'device': e.device,
                'activity': e.activity,
                'timestamp': e.timestamp.isoformat(),
                'time_formatted': e.timestamp.strftime('%H:%M:%S'),
                'suspicious': e.suspicious,
                'flags': e.flags
            }
            for e in sorted_events
        ]
    })

@app.route('/api/graph', methods=['GET'])
def get_graph():
    """Get graph visualization data"""
    nodes = []
    edges = []
    
    for event_id, event in graph.nodes.items():
        nodes.append({
            'id': event_id,
            'label': f"{event.activity[:20]}...",
            'user': event.user,
            'device': event.device,
            'suspicious': event.suspicious,
            'timestamp': event.timestamp.isoformat()
        })
    
    for from_id, neighbors in graph.edges.items():
        for to_id, cost in neighbors:
            edges.append({
                'source': from_id,
                'target': to_id,
                'cost': round(cost, 2)
            })
    
    return jsonify({'nodes': nodes, 'edges': edges})

@app.route('/api/generate-report', methods=['GET'])
def generate_report():
    """Generate investigation report"""
    dataset_hash = hashlib.sha256(
        json.dumps([
            {
                'id': e.event_id,
                'user': e.user,
                'device': e.device,
                'activity': e.activity,
                'timestamp': e.timestamp.isoformat()
            }
            for e in all_events
        ], default=str).encode()
    ).hexdigest()
    
    return jsonify({
        'report': {
            'title': 'Digital Forensic Investigation Report',
            'generated': datetime.now().isoformat(),
            'total_events': len(all_events),
            'suspicious_events': len([e for e in all_events if e.suspicious]),
            'total_graph_edges': sum(len(edges) for edges in graph.edges.values()),
            'dataset_integrity_hash': dataset_hash,
            'algorithms_implemented': ['BFS', 'DFS', 'Uniform Cost Search'],
            'events': [
                {
                    'id': e.event_id,
                    'user': e.user,
                    'device': e.device,
                    'activity': e.activity,
                    'timestamp': e.timestamp.isoformat(),
                    'suspicious': e.suspicious,
                    'flags': e.flags
                }
                for e in all_events
            ]
        }
    })

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def calculate_path_cost(graph: EvidenceGraph, path: List[str]) -> float:
    """Calculate total cost of a path"""
    cost = 0
    for i in range(len(path) - 1):
        for neighbor_id, edge_cost in graph.get_neighbors(path[i]):
            if neighbor_id == path[i+1]:
                cost += edge_cost
                break
    return cost
if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=5000)

@app.route('/')
def home():
    return jsonify({'message': 'Forensic Investigation API is running', 'endpoints': [
        '/api/load-dataset (POST)',
        '/api/events (GET)',
        '/api/suspicious-activities (GET)',
        '/api/timeline (GET)',
        '/api/graph (GET)',
        '/api/search (POST)',
        '/api/compare-algorithms (POST)',
        '/api/generate-report (GET)'
    ]})

