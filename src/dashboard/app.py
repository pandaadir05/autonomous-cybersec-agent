"""
Simple web dashboard for Lesh security agent.
"""

import dash
from dash import dcc, html
from dash.dependencies import Input, Output
import plotly.graph_objs as go
import pandas as pd
import json
import os
from datetime import datetime
import time

# Initialize the Dash app
app = dash.Dash(__name__, title="Lesh Security Dashboard")

# Layout for the dashboard
app.layout = html.Div([
    html.H1("Lesh Cybersecurity Dashboard"),
    html.Div([
        html.Button('Refresh Data', id='refresh-button', n_clicks=0),
        html.Div(id='last-refresh', children='Never refreshed')
    ]),
    
    html.Div([
        html.H2("Threat Detection Summary"),
        dcc.Graph(id='threat-summary-graph'),
    ]),
    
    html.Div([
        html.H2("Recent Security Events"),
        html.Div(id='recent-events-table')
    ]),
    
    # Auto refresh every 30 seconds
    dcc.Interval(id='interval-component', interval=30*1000, n_intervals=0)
])

# Load threat data (in a real implementation, this would connect to the agent)
def load_threat_data():
    # This is a sample implementation - would connect to the agent API
    try:
        # For now, generate sample data
        data = {
            'threat_types': {
                'suspicious_connection': 12,
                'suspicious_process': 5,
                'brute_force_attempt': 3,
                'system_anomaly': 2
            },
            'recent_events': [
                {'timestamp': time.time() - 120, 'type': 'suspicious_connection', 'source': '192.168.1.155', 'severity': 3},
                {'timestamp': time.time() - 300, 'type': 'suspicious_process', 'source': 'PID:1234', 'severity': 4},
                {'timestamp': time.time() - 600, 'type': 'brute_force_attempt', 'source': '10.0.0.12', 'severity': 3},
            ]
        }
        return data
    except Exception as e:
        print(f"Error loading threat data: {e}")
        return {'threat_types': {}, 'recent_events': []}

# Callback for refreshing the dashboard
@app.callback(
    [Output('threat-summary-graph', 'figure'), 
     Output('recent-events-table', 'children'),
     Output('last-refresh', 'children')],
    [Input('refresh-button', 'n_clicks'),
     Input('interval-component', 'n_intervals')]
)
def update_dashboard(n_clicks, n_intervals):
    data = load_threat_data()
    
    # Create threat summary chart
    threat_types = list(data['threat_types'].keys())
    threat_counts = list(data['threat_types'].values())
    
    figure = {
        'data': [go.Bar(
            x=threat_types,
            y=threat_counts,
            marker=dict(color=['#2196F3', '#FF9800', '#F44336', '#4CAF50'])
        )],
        'layout': go.Layout(
            title='Threats by Type',
            height=400,
            margin=dict(l=40, r=40, t=40, b=40),
            xaxis={'title': 'Threat Type'},
            yaxis={'title': 'Count'}
        )
    }
    
    # Create recent events table
    events = data['recent_events']
    table_rows = [html.Tr([
        html.Th("Time"),
        html.Th("Type"),
        html.Th("Source"),
        html.Th("Severity")
    ])]
    
    for event in events:
        time_str = datetime.fromtimestamp(event['timestamp']).strftime('%H:%M:%S')
        severity_color = {
            1: 'lightblue',
            2: 'lightgreen',
            3: 'yellow',
            4: 'orange',
            5: 'red'
        }.get(event['severity'], 'white')
        
        table_rows.append(html.Tr([
            html.Td(time_str),
            html.Td(event['type']),
            html.Td(event['source']),
            html.Td(event['severity'], style={'background-color': severity_color})
        ]))
    
    events_table = html.Table(table_rows, style={'width': '100%'})
    
    # Update refresh time
    refresh_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    return figure, events_table, f"Last refreshed: {refresh_time}"

# Run the dashboard
if __name__ == '__main__':
    app.run_server(debug=True)
