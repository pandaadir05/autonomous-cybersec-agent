"""
Advanced Cybersecurity Dashboard for the Autonomous Agent.
Features dynamic visualizations, real-time metrics, and futuristic UI elements.
"""

import dash
from dash import html, dcc, Input, Output, State
import dash_bootstrap_components as dbc
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from datetime import datetime, timedelta
import pandas as pd
import numpy as np
import random
import time
import os
import json
import logging
from typing import List, Dict, Any, Optional

# Configure logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Initialize the Dash app with dark theme for cybersecurity focus
app = dash.Dash(
    __name__, 
    external_stylesheets=[
        dbc.themes.CYBORG, 
        'https://use.fontawesome.com/releases/v5.15.4/css/all.css',
        'https://fonts.googleapis.com/css2?family=Orbitron:wght@400;500;700&family=Roboto+Mono:wght@300;400;500&family=Roboto:wght@300;400;500;700&display=swap'
    ],
    meta_tags=[
        {"name": "viewport", "content": "width=device-width, initial-scale=1"}
    ],
    suppress_callback_exceptions=True,
    title="LESH Cybersecurity Command Center"
)

# Define the layout
app.layout = dbc.Container([
    # Cyber grid background
    html.Div(className="cyber-grid-bg"),
    html.Div(className="cyber-particles"),

    # Header with logo and status
    dbc.Row([
        dbc.Col([
            html.Div([
                html.Div([
                    html.I(className="fas fa-shield-alt me-2"),
                    html.Span("LESH", className="logo-text")
                ], className="dashboard-logo"),
                html.Div([
                    html.H1("Cybersecurity Command Center", className="header-title"),
                    html.H2("Advanced Threat Defense System", className="header-subtitle")
                ], className="dashboard-title-container")
            ], className="d-flex align-items-center")
        ], width=8, className="header-left"),
        
        dbc.Col([
            html.Div([
                html.Div(id="security-status-indicator", className="status-indicator secure"),
                html.Div([
                    html.Div(id="current-time", className="time-display"),
                    html.Div(id="system-uptime", className="uptime-display")
                ], className="time-container")
            ], className="d-flex flex-column align-items-end")
        ], width=4, className="header-right")
    ], className="dashboard-header mb-4"),
    
    # Main content with metrics and visualizations
    dbc.Row([
        # Left sidebar with metrics cards
        dbc.Col([
            # Threat Analysis Card
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fas fa-chart-line me-2"),
                    html.Span("THREAT ANALYSIS", className="card-header-text")
                ], className="metric-header"),
                dbc.CardBody([
                    dbc.Row([
                        dbc.Col([
                            html.Div([
                                html.H3(id="active-threats-counter", className="metric-value"),
                                html.Div("Active Threats", className="metric-label")
                            ], className="metric-container")
                        ], width=6),
                        dbc.Col([
                            html.Div([
                                html.H3(id="critical-events-counter", className="metric-value"),
                                html.Div("Critical Events", className="metric-label")
                            ], className="metric-container")
                        ], width=6)
                    ], className="mb-3"),
                    dbc.Row([
                        dbc.Col([
                            html.Div([
                                html.H3(id="threats-blocked-counter", className="metric-value"),
                                html.Div("Threats Blocked", className="metric-label")
                            ], className="metric-container")
                        ], width=6),
                        dbc.Col([
                            html.Div([
                                html.H3(id="avg-response-time", className="metric-value"),
                                html.Div("Avg Response", className="metric-label")
                            ], className="metric-container")
                        ], width=6)
                    ])
                ])
            ], className="metric-card mb-4"),
            
            # System Health Card
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fas fa-heartbeat me-2"),
                    html.Span("SYSTEM HEALTH", className="card-header-text")
                ], className="metric-header"),
                dbc.CardBody([
                    html.Div([
                        html.Div(id="system-health-indicator", className="health-indicator"),
                        html.Div(id="health-status-chart", className="health-chart-container")
                    ], className="d-flex align-items-center justify-content-between mb-3"),
                    html.Div(id="system-resources", className="resource-metrics")
                ])
            ], className="metric-card mb-4"),
            
            # Security Feed Card
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fas fa-rss me-2"),
                    html.Span("SECURITY FEED", className="card-header-text")
                ], className="metric-header d-flex justify-content-between"),
                dbc.CardBody([
                    html.Div(id="security-feed-container", className="security-feed")
                ])
            ], className="metric-card feed-card")
            
        ], width=3, className="dashboard-sidebar"),
        
        # Main visualizations area
        dbc.Col([
            # Tabs for different visualization sections
            dbc.Tabs([
                # Overview Tab
                dbc.Tab(label="Overview", tabClassName="custom-tab", activeTabClassName="custom-tab-active", children=[
                    dbc.Card([
                        dbc.CardBody([
                            dbc.Row([
                                dbc.Col(dcc.Graph(id="threat-timeline", className="chart-container", config={'displayModeBar': False}), width=12),
                            ], className="mb-4"),
                            dbc.Row([
                                dbc.Col(dcc.Graph(id="threat-distribution", className="chart-container", config={'displayModeBar': False}), width=6),
                                dbc.Col(dcc.Graph(id="threat-types", className="chart-container", config={'displayModeBar': False}), width=6),
                            ])
                        ])
                    ], className="visualization-card")
                ]),
                
                # Network Tab
                dbc.Tab(label="Network", tabClassName="custom-tab", activeTabClassName="custom-tab-active", children=[
                    dbc.Card([
                        dbc.CardBody([
                            dbc.Row([
                                dbc.Col(dcc.Graph(id="network-map", className="chart-container map-container", config={'displayModeBar': False}), width=12),
                            ], className="mb-4"),
                            dbc.Row([
                                dbc.Col(dcc.Graph(id="network-traffic", className="chart-container", config={'displayModeBar': False}), width=12),
                            ])
                        ])
                    ], className="visualization-card")
                ]),
                
                # System Tab
                dbc.Tab(label="System", tabClassName="custom-tab", activeTabClassName="custom-tab-active", children=[
                    dbc.Card([
                        dbc.CardBody([
                            dbc.Row([
                                dbc.Col(dcc.Graph(id="cpu-usage", className="chart-container", config={'displayModeBar': False}), width=6),
                                dbc.Col(dcc.Graph(id="memory-usage", className="chart-container", config={'displayModeBar': False}), width=6),
                            ], className="mb-4"),
                            dbc.Row([
                                dbc.Col(dcc.Graph(id="disk-io", className="chart-container", config={'displayModeBar': False}), width=12),
                            ])
                        ])
                    ], className="visualization-card")
                ]),
                
                # Alerts Tab
                dbc.Tab(label="Alerts", tabClassName="custom-tab", activeTabClassName="custom-tab-active", children=[
                    dbc.Card([
                        dbc.CardBody([
                            html.Div([
                                dbc.ButtonGroup([
                                    dbc.Button("All", id="filter-all", color="primary", className="filter-btn active", n_clicks=0),
                                    dbc.Button("Critical", id="filter-critical", color="danger", className="filter-btn", n_clicks=0),
                                    dbc.Button("High", id="filter-high", color="warning", className="filter-btn", n_clicks=0),
                                    dbc.Button("Medium", id="filter-medium", color="info", className="filter-btn", n_clicks=0),
                                    dbc.Button("Low", id="filter-low", color="success", className="filter-btn", n_clicks=0)
                                ], className="alert-filters mb-3")
                            ]),
                            html.Div(id="alerts-container", className="alerts-log")
                        ])
                    ], className="visualization-card")
                ]),
                
                # Advanced Tab with 3D visualization
                dbc.Tab(label="Advanced", tabClassName="custom-tab", activeTabClassName="custom-tab-active", children=[
                    dbc.Card([
                        dbc.CardBody([
                            dbc.Row([
                                dbc.Col(dcc.Graph(id="threat-landscape-3d", className="chart-container", config={'displayModeBar': False}), width=12),
                            ], className="mb-4"),
                            dbc.Row([
                                dbc.Col([
                                    html.Div(id="advanced-analytics", className="advanced-analytics-container")
                                ], width=12)
                            ])
                        ])
                    ], className="visualization-card")
                ]),
                
            ], id="viz-tabs", active_tab="tab-1", className="custom-tabs")
        ], width=9, className="main-content")
    ], className="main-row"),
    
    # Footer section
    dbc.Row([
        dbc.Col([
            html.Div([
                html.Span("LESH Autonomous Cybersecurity Defense Agent", className="footer-brand"),
                html.Span("•", className="footer-dot"),
                html.Span(id="agent-version", children="v1.0.0", className="footer-version"),
                html.Div([
                    html.Div([
                        html.Span("API", className="status-label"),
                        html.Span(id="api-status", className="status-indicator-small online")
                    ], className="status-item"),
                    html.Div([
                        html.Span("ML", className="status-label"),
                        html.Span(id="ml-status", className="status-indicator-small online")
                    ], className="status-item"),
                    html.Div([
                        html.Span("DB", className="status-label"),
                        html.Span(id="db-status", className="status-indicator-small online")
                    ], className="status-item")
                ], className="system-statuses")
            ], className="footer-content")
        ], width=12)
    ], className="dashboard-footer"),
    
    # Hidden components for updates
    dcc.Interval(id="fast-interval", interval=1000, n_intervals=0),  # 1 second
    dcc.Interval(id="medium-interval", interval=3000, n_intervals=0),  # 3 seconds
    dcc.Interval(id="slow-interval", interval=10000, n_intervals=0),  # 10 seconds
    dcc.Store(id="app-state")
    
], fluid=True, className="dashboard-container")

# === CALLBACK FUNCTIONS ===

# Update time displays
@app.callback(
    [Output("current-time", "children"),
     Output("system-uptime", "children")],
    Input("fast-interval", "n_intervals")
)
def update_time_displays(n_intervals):
    current_time = datetime.now().strftime("%H:%M:%S")
    
    # Calculate uptime from a simulated start time
    start_time = datetime.now() - timedelta(hours=n_intervals // 3600, 
                                          minutes=(n_intervals % 3600) // 60, 
                                          seconds=n_intervals % 60)
    
    uptime_hours = (datetime.now() - start_time).total_seconds() / 3600
    
    if uptime_hours < 24:
        uptime_str = f"{int(uptime_hours)}h {int((uptime_hours % 1) * 60)}m"
    else:
        uptime_days = int(uptime_hours / 24)
        remaining_hours = int(uptime_hours % 24)
        uptime_str = f"{uptime_days}d {remaining_hours}h"
    
    return current_time, f"Uptime: {uptime_str}"

# Security status indicator
@app.callback(
    Output("security-status-indicator", "className"),
    Input("medium-interval", "n_intervals")
)
def update_security_status(n_intervals):
    # Simulate a changing security status
    status_seed = (n_intervals // 10) % 10  # Change status every ~30 seconds
    random.seed(status_seed)
    status_roll = random.random()
    
    if status_roll > 0.9:
        return "status-indicator critical pulse"
    elif status_roll > 0.75:
        return "status-indicator warning"
    else:
        return "status-indicator secure"

# Update threat metrics
@app.callback(
    [Output("active-threats-counter", "children"),
     Output("critical-events-counter", "children"),
     Output("threats-blocked-counter", "children"),
     Output("avg-response-time", "children")],
    Input("medium-interval", "n_intervals")
)
def update_threat_metrics(n_intervals):
    # Simulate changing threat metrics with some randomization but stability
    random.seed(n_intervals // 5)  # Change core values every ~15 seconds
    
    # Active threats: typically low number with occasional spikes
    active_base = 2 if random.random() > 0.8 else 1
    active_threats = active_base + random.randint(0, 3)
    
    # Critical events: cumulative count that grows over time
    critical_events = 3 + (n_intervals // 20) + random.randint(0, 2)
    
    # Threats blocked: larger cumulative number that grows over time
    threats_blocked = 42 + (n_intervals // 4) + random.randint(0, 5)
    
    # Average response time: stable with minor fluctuations, in ms
    avg_response = 230 + random.randint(-30, 50)
    
    return str(active_threats), str(critical_events), str(threats_blocked), f"{avg_response}ms"

# System health indicator and resources
@app.callback(
    [Output("system-health-indicator", "children"),
     Output("system-health-indicator", "className"),
     Output("health-status-chart", "children"),
     Output("system-resources", "children")],
    Input("medium-interval", "n_intervals")
)
def update_system_health(n_intervals):
    # Determine health status
    health_seed = (n_intervals // 8) % 15  # Change health status every ~24 seconds
    random.seed(health_seed)
    health_roll = random.random()
    
    if health_roll > 0.9:
        status = "Critical"
        status_class = "health-indicator critical"
    elif health_roll > 0.75:
        status = "Warning"
        status_class = "health-indicator warning"
    else:
        status = "Healthy"
        status_class = "health-indicator healthy"
    
    # Generate health sparkline data
    health_data = []
    for i in range(15):
        point_seed = (n_intervals - 14 + i)
        random.seed(point_seed)
        if i >= 12:  # Most recent data points
            # Align with current status
            if status == "Critical":
                health_data.append(random.uniform(0.1, 0.3))
            elif status == "Warning":
                health_data.append(random.uniform(0.4, 0.6))
            else:
                health_data.append(random.uniform(0.7, 0.9))
        else:
            # Historical data with some variability
            health_data.append(random.uniform(0.3, 0.9))
    
    # Create mini sparkline chart for health trend
    spark_fig = go.Figure(go.Scatter(
        y=health_data,
        mode='lines',
        line=dict(width=2, color='rgba(0, 176, 246, 0.8)'),
        fill='tozeroy',
        fillcolor='rgba(0, 176, 246, 0.2)'
    ))
    
    # Style the sparkline
    spark_fig.update_layout(
        height=35,
        width=100,
        margin=dict(l=0, r=0, t=0, b=0, pad=0),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        xaxis=dict(
            showgrid=False,
            zeroline=False,
            showticklabels=False,
            fixedrange=True
        ),
        yaxis=dict(
            showgrid=False,
            zeroline=False,
            showticklabels=False,
            range=[0, 1],
            fixedrange=True
        ),
        showlegend=False,
    )
    
    # Spark chart component
    health_chart = dcc.Graph(
        figure=spark_fig,
        config={'displayModeBar': False},
        style={'height': '35px', 'width': '100px'}
    )
    
    # Generate system resource metrics
    random.seed(n_intervals)
    cpu_usage = random.randint(15, 45)
    memory_usage = random.randint(30, 70)
    disk_usage = random.randint(40, 85)
    network_usage = random.randint(5, 60)
    
    # Resource indicators
    resources = html.Div([
        html.Div([
            html.Div([
                html.Span("CPU", className="resource-label"),
                html.Span(f"{cpu_usage}%", className="resource-value")
            ], className="resource-text"),
            dbc.Progress(value=cpu_usage, className="resource-bar", 
                        color="success" if cpu_usage < 70 else "warning" if cpu_usage < 90 else "danger")
        ], className="resource-item"),
        html.Div([
            html.Div([
                html.Span("MEM", className="resource-label"),
                html.Span(f"{memory_usage}%", className="resource-value")
            ], className="resource-text"),
            dbc.Progress(value=memory_usage, className="resource-bar",
                        color="success" if memory_usage < 70 else "warning" if memory_usage < 90 else "danger")
        ], className="resource-item"),
        html.Div([
            html.Div([
                html.Span("DISK", className="resource-label"),
                html.Span(f"{disk_usage}%", className="resource-value")
            ], className="resource-text"),
            dbc.Progress(value=disk_usage, className="resource-bar",
                        color="success" if disk_usage < 70 else "warning" if disk_usage < 90 else "danger")
        ], className="resource-item"),
        html.Div([
            html.Div([
                html.Span("NET", className="resource-label"),
                html.Span(f"{network_usage}%", className="resource-value")
            ], className="resource-text"),
            dbc.Progress(value=network_usage, className="resource-bar",
                        color="success" if network_usage < 70 else "warning" if network_usage < 90 else "danger")
        ], className="resource-item")
    ], className="resources-container")
    
    return status, status_class, health_chart, resources

# Security feed updates
@app.callback(
    Output("security-feed-container", "children"),
    Input("slow-interval", "n_intervals")
)
def update_security_feed(n_intervals):
    # Security event templates with severity levels
    security_events = [
        {"text": "New ransomware signature detected and blocked", "severity": "critical", "icon": "fas fa-bug"},
        {"text": "Failed login attempt from unauthorized location", "severity": "high", "icon": "fas fa-user-shield"},
        {"text": "Windows security patch KB45892 deployed", "severity": "info", "icon": "fas fa-download"},
        {"text": "Suspicious outbound connection blocked", "severity": "medium", "icon": "fas fa-filter"},
        {"text": "Potential SQL injection attempt detected", "severity": "high", "icon": "fas fa-code"},
        {"text": "System scan complete - 0 vulnerabilities", "severity": "info", "icon": "fas fa-search"},
        {"text": "New IoT device connected to network", "severity": "medium", "icon": "fas fa-wifi"},
        {"text": "DNS request to blacklisted domain blocked", "severity": "high", "icon": "fas fa-ban"},
        {"text": "File quarantined: Trojan.Win32.Exploit", "severity": "critical", "icon": "fas fa-file-code"},
        {"text": "Firewall rules updated successfully", "severity": "info", "icon": "fas fa-shield-alt"},
        {"text": "DDoS protection activated", "severity": "high", "icon": "fas fa-bolt"},
        {"text": "User account permissions modified", "severity": "medium", "icon": "fas fa-users-cog"}
    ]
    
    # Generate timestamps for alerts (newest to oldest)
    now = datetime.now()
    alerts = []
    
    for i in range(8):  # Generate 8 most recent alerts
        template_idx = random.randint(0, len(security_events)-1)
        alert = security_events[template_idx].copy()
        
        # Add more randomized fields
        minutes_ago = i * 7 + random.randint(0, 5)  # Spread out alerts
        alert["time"] = (now - timedelta(minutes=minutes_ago)).strftime("%H:%M")
        
        alerts.append(alert)
    
    # Create feed items
    feed_items = []
    for alert in alerts:
        severity_class = f"feed-icon {alert['severity']}"
        
        feed_items.append(
            html.Div([
                html.Div([
                    html.I(className=alert["icon"]),
                ], className=severity_class),
                html.Div([
                    html.Div(alert["text"], className="feed-text"),
                    html.Div(alert["time"], className="feed-time"),
                ], className="feed-content")
            ], className="feed-item")
        )
    
    return feed_items

# Define other core callbacks like threat-timeline, threat-distribution, etc.
@app.callback(
    Output("threat-timeline", "figure"),
    Input("medium-interval", "n_intervals")
)
def update_threat_timeline(n_intervals):
    # Generate threat timeline data
    now = datetime.now()
    hours = 24
    timestamps = [(now - timedelta(hours=i)).strftime("%Y-%m-%d %H:%M") for i in range(hours, 0, -1)]
    
    # Create a base pattern with some periodicity plus noise
    base_pattern = [5 + 3 * np.sin(i/4) + 2 * np.cos(i/2) for i in range(hours)]
    random.seed(n_intervals // 10)  # Change core pattern periodically
    event_counts = [max(0, round(val + random.uniform(-1.0, 1.5))) for val in base_pattern]
    
    # Create moving average for trend line
    window_size = 3
    moving_avg = []
    for i in range(len(event_counts)):
        if i < window_size:
            moving_avg.append(np.mean(event_counts[:i+1]))
        else:
            moving_avg.append(np.mean(event_counts[i-window_size+1:i+1]))
    
    # Create figure with two y-axes
    fig = make_subplots(specs=[[{"secondary_y": True}]])
    
    # Add main event count area
    fig.add_trace(
        go.Scatter(
            x=timestamps, 
            y=event_counts,
            name="Events",
            line=dict(width=2, color='rgba(0, 176, 246, 0.8)'),
            fill='tozeroy',
            fillcolor='rgba(0, 176, 246, 0.3)',
            hovertemplate="Time: %{x}<br>Events: %{y}<extra></extra>"
        )
    )
    
    # Add moving average line
    fig.add_trace(
        go.Scatter(
            x=timestamps,
            y=moving_avg,
            name="Trend",
            line=dict(width=2, color='rgba(231, 107, 243, 0.8)', dash='dot'),
            hovertemplate="Time: %{x}<br>Trend: %{y:.1f}<extra></extra>"
        )
    )
    
    # Style the figure for maximum visibility on dark backgrounds
    fig.update_layout(
        title={
            'text': "Security Event Timeline",
            'y': 0.95,
            'x': 0.5,
            'xanchor': 'center',
            'yanchor': 'top',
            'font': {'size': 20, 'color': 'white'}
        },
        font={'color': 'white', 'family': 'Roboto'},
        template="plotly_dark",
        plot_bgcolor="rgba(30, 40, 60, 0.8)",  # More visible background
        paper_bgcolor="rgba(30, 40, 60, 0.8)",  # More visible background
        xaxis=dict(
            title="Time",
            title_font=dict(color='white', size=14),
            showgrid=True,
            gridcolor="rgba(255, 255, 255, 0.15)",  # More visible grid
            tickfont=dict(color='white', size=12),
        ),
        yaxis=dict(
            title="Event Count",
            title_font=dict(color='white', size=14),
            showgrid=True,
            gridcolor="rgba(255, 255, 255, 0.15)",  # More visible grid
            tickfont=dict(color='white'),
        ),
        margin=dict(l=40, r=20, t=60, b=40),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1,
            font=dict(color="white", size=12),
            bgcolor="rgba(30, 40, 60, 0.8)",  # More visible legend background
            bordercolor="rgba(255, 255, 255, 0.2)",
            borderwidth=1
        ),
        hovermode="closest",
        height=300,
        autosize=True
    )
    
    return fig

@app.callback(
    Output("threat-distribution", "figure"),
    Input("medium-interval", "n_intervals")
)
def update_threat_distribution(n_intervals):
    # Generate threat severity distribution
    random.seed(n_intervals // 7)  # Change distribution periodically
    
    labels = ["Critical", "High", "Medium", "Low"]
    values = [
        random.randint(1, 5),
        random.randint(5, 15),
        random.randint(15, 30),
        random.randint(20, 40)
    ]
    
    # Create enhanced pie chart
    fig = go.Figure()
    
    # Add pie chart with custom styling
    fig.add_trace(go.Pie(
        labels=labels,
        values=values,
        hole=0.6,
        textinfo="label+percent",
        hoverinfo="label+percent+value",
        textfont=dict(color='white', size=12),
        marker=dict(
            colors=["#ff4136", "#ff851b", "#ffdc00", "#2ecc40"],
            line=dict(color="#111111", width=1)
        ),
        pull=[0.05, 0.02, 0, 0]  # Pull out critical slice slightly
    ))
    
    # Add central text
    fig.add_annotation(
        text=f"{sum(values)}<br>Events",
        x=0.5, y=0.5,
        font_size=16,
        font_color='white',
        showarrow=False
    )
    
    # Style the figure for visibility on dark backgrounds
    fig.update_layout(
        title={
            'text': "Event Severity Distribution",
            'y': 0.95,
            'x': 0.5,
            'xanchor': 'center',
            'yanchor': 'top',
            'font': {'size': 20, 'color': 'white'}
        },
        font={'color': 'white'},
        template="plotly_dark",
        plot_bgcolor="rgba(0, 0, 0, 0)",
        paper_bgcolor="rgba(0, 0, 0, 0)",
        legend=dict(
            orientation="v",
            yanchor="middle",
            y=0.5,
            xanchor="right",
            x=1.05,
            font=dict(size=12, color='white'),
            bgcolor="rgba(30, 30, 40, 0.5)",
        ),
        margin=dict(l=20, r=100, t=60, b=20),
        height=300,
        autosize=True,
        showlegend=True
    )
    
    return fig

# Run the application
def run_dashboard(debug=False):
    """Run the dashboard application."""
    # Pass debug mode from caller
    app.run(debug=debug, port=8050)

def app_run():
    """Run the dashboard application without debug mode (safe for threading)."""
    import threading
    if threading.current_thread() is threading.main_thread():
        # In main thread, can use debug mode
        app.run(debug=True, port=8050)
    else:
        # In non-main thread, must disable debug mode
        app.run(debug=False, port=8050)

if __name__ == "__main__":
    # When run directly, enable debug mode
    run_dashboard(debug=True)
