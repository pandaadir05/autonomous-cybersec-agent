"""
Agent status page - displays real-time status and health information
"""
import dash
from dash import html, dcc, callback
import dash_bootstrap_components as dbc
from dash.dependencies import Input, Output, State
import plotly.graph_objects as go
import plotly.express as px
import numpy as np
import pandas as pd
import psutil
import time
import os
import socket
import platform
import random
from datetime import datetime, timedelta

# Create the status page app
app = dash.Dash(
    __name__,
    external_stylesheets=[
        dbc.themes.CYBORG,
        "https://use.fontawesome.com/releases/v5.15.4/css/all.css"
    ]
)

# Define layout with health metrics
app.layout = dbc.Container([
    # Header
    dbc.Row([
        dbc.Col([
            html.H1([
                html.I(className="fas fa-heartbeat mr-2"),
                "LESH Agent Status Monitor"
            ], className="text-center mb-4 mt-4")
        ])
    ]),
    
    # System Status Card
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.H3("System Status", className="card-title")
                ], className="bg-primary"),
                dbc.CardBody([
                    dbc.Row([
                        # System Overview
                        dbc.Col([
                            html.Div([
                                html.H5("System Overview"),
                                html.P(id="system-overview"),
                                html.Div([
                                    html.Span("Status:"),
                                    html.Span(id="agent-status", className="badge bg-success ms-2")
                                ], className="d-flex align-items-center mb-2"),
                                html.Div([
                                    html.Span("Hostname:"),
                                    html.Span(id="hostname", className="ms-2")
                                ], className="d-flex align-items-center mb-2"),
                                html.Div([
                                    html.Span("IP Address:"),
                                    html.Span(id="ip-address", className="ms-2")
                                ], className="d-flex align-items-center mb-2"),
                                html.Div([
                                    html.Span("Platform:"),
                                    html.Span(id="platform", className="ms-2")
                                ], className="d-flex align-items-center mb-2"),
                                html.Div([
                                    html.Span("Uptime:"),
                                    html.Span(id="system-uptime", className="ms-2")
                                ], className="d-flex align-items-center")
                            ], className="mb-4")
                        ], width=4),
                        
                        # Resource Usage
                        dbc.Col([
                            html.H5("Resource Usage"),
                            html.Div([
                                html.Div([
                                    html.Span("CPU:"),
                                    html.Div([
                                        dbc.Progress(id="cpu-progress", className="mb-0")
                                    ], className="ms-2 flex-grow-1")
                                ], className="d-flex align-items-center mb-3"),
                                html.Div([
                                    html.Span("Memory:"),
                                    html.Div([
                                        dbc.Progress(id="memory-progress", className="mb-0")
                                    ], className="ms-2 flex-grow-1")
                                ], className="d-flex align-items-center mb-3"),
                                html.Div([
                                    html.Span("Disk:"),
                                    html.Div([
                                        dbc.Progress(id="disk-progress", className="mb-0")
                                    ], className="ms-2 flex-grow-1")
                                ], className="d-flex align-items-center mb-3"),
                                html.Div([
                                    html.Span("Network:"),
                                    html.Span(id="network-usage", className="ms-2")
                                ], className="d-flex align-items-center mb-3")
                            ])
                        ], width=4),
                        
                        # Agent Components
                        dbc.Col([
                            html.H5("Agent Components"),
                            html.Table([
                                html.Thead([
                                    html.Tr([
                                        html.Th("Component"),
                                        html.Th("Status")
                                    ])
                                ]),
                                html.Tbody(id="component-status")
                            ], className="table table-dark table-striped")
                        ], width=4)
                    ])
                ])
            ], className="mb-4")
        ])
    ]),
    
    # Charts
    dbc.Row([
        # CPU Usage History
        dbc.Col([
            dbc.Card([
                dbc.CardHeader("CPU Usage History"),
                dbc.CardBody([
                    dcc.Graph(id="cpu-chart", config={'displayModeBar': False})
                ])
            ])
        ], width=6),
        
        # Memory Usage History
        dbc.Col([
            dbc.Card([
                dbc.CardHeader("Memory Usage History"),
                dbc.CardBody([
                    dcc.Graph(id="memory-chart", config={'displayModeBar': False})
                ])
            ])
        ], width=6)
    ], className="mb-4"),
    
    # Logs and Actions
    dbc.Row([
        # Recent Logs
        dbc.Col([
            dbc.Card([
                dbc.CardHeader("Recent Logs"),
                dbc.CardBody([
                    html.Div(id="recent-logs", className="logs-container")
                ], style={"maxHeight": "250px", "overflow": "auto"})
            ])
        ], width=7),
        
        # Actions
        dbc.Col([
            dbc.Card([
                dbc.CardHeader("Agent Actions"),
                dbc.CardBody([
                    dbc.Button("Restart Agent", id="restart-button", color="warning", className="me-2 mb-2"),
                    dbc.Button("Stop Agent", id="stop-button", color="danger", className="me-2 mb-2"),
                    dbc.Button("Run Diagnostic", id="diagnostic-button", color="info", className="me-2 mb-2"),
                    dbc.Button("Refresh Data", id="refresh-button", color="primary", className="mb-2"),
                    html.Div(id="action-feedback", className="mt-3")
                ])
            ])
        ], width=5)
    ]),
    
    # Update intervals
    dcc.Interval(id="fast-interval", interval=1000),  # 1 second for time
    dcc.Interval(id="medium-interval", interval=5000),  # 5 seconds for system stats
    dcc.Interval(id="slow-interval", interval=60000),  # 60 seconds for history data
    
    # Store components
    dcc.Store(id="cpu-history", data=[]),
    dcc.Store(id="memory-history", data=[]),
    
    # Footer
    dbc.Row([
        dbc.Col([
            html.Footer([
                html.P("LESH Autonomous Cybersecurity Defense Agent - Status Monitor", className="text-center text-muted mt-4")
            ])
        ])
    ])
], fluid=True)

# Callback for system overview
@app.callback(
    [
        Output("system-overview", "children"),
        Output("agent-status", "children"),
        Output("agent-status", "className"),
        Output("hostname", "children"),
        Output("ip-address", "children"),
        Output("platform", "children"),
        Output("system-uptime", "children"),
        Output("cpu-progress", "value"),
        Output("cpu-progress", "color"),
        Output("memory-progress", "value"),
        Output("memory-progress", "color"),
        Output("disk-progress", "value"),
        Output("disk-progress", "color"),
        Output("network-usage", "children"),
        Output("component-status", "children")
    ],
    [Input("medium-interval", "n_intervals")]
)
def update_system_status(n):
    # Get current time for simulated uptime
    now = datetime.now()
    startup_time = now - timedelta(hours=24, minutes=36, seconds=15)  # Simulated startup time
    uptime_secs = (now - startup_time).total_seconds()
    
    # Format uptime string
    days = int(uptime_secs // (24 * 3600))
    uptime_secs = uptime_secs % (24 * 3600)
    hours = int(uptime_secs // 3600)
    uptime_secs %= 3600
    minutes = int(uptime_secs // 60)
    uptime_str = f"{days}d {hours}h {minutes}m"
    
    # Get system info
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
    except:
        hostname = "Unknown"
        ip_address = "Unknown"
        
    platform_str = f"{platform.system()} {platform.release()}"
    
    # Get resource usage
    cpu_percent = psutil.cpu_percent()
    memory = psutil.virtual_memory()
    memory_percent = memory.percent
    
    # Get disk usage for primary disk
    disk = psutil.disk_usage('/')
    disk_percent = disk.percent
    
    # Get network stats
    net_io = psutil.net_io_counters()
    net_sent_mb = net_io.bytes_sent / (1024 * 1024)
    net_recv_mb = net_io.bytes_recv / (1024 * 1024)
    network_str = f"Sent: {net_sent_mb:.1f}MB, Recv: {net_recv_mb:.1f}MB"
    
    # Progress bar colors
    cpu_color = "success" if cpu_percent < 70 else "warning" if cpu_percent < 90 else "danger"
    memory_color = "success" if memory_percent < 70 else "warning" if memory_percent < 90 else "danger"
    disk_color = "success" if disk_percent < 80 else "warning" if disk_percent < 90 else "danger"
    
    # Set agent status
    if cpu_percent > 90 or memory_percent > 90:
        agent_status = "Under Stress"
        status_class = "badge bg-danger ms-2"
    elif cpu_percent > 70 or memory_percent > 70:
        agent_status = "High Load"
        status_class = "badge bg-warning ms-2"
    else:
        agent_status = "Operational"
        status_class = "badge bg-success ms-2"
    
    # System overview text
    overview = f"Agent has been running since {startup_time.strftime('%Y-%m-%d %H:%M:%S')}"
    
    # Component statuses
    components = []
    component_statuses = [
        {"name": "Detection Engine", "status": "Active", "badge": "success"},
        {"name": "Response Module", "status": "Active", "badge": "success"},
        {"name": "Analytics Engine", "status": "Active", "badge": "success"},
        {"name": "ML Model", "status": "Active", "badge": "success"},
        {"name": "API Server", "status": "Active", "badge": "success"}
    ]
    
    # Randomly simulate one component issue
    if n % 20 == 0:  # Every 20 updates (100 seconds)
        issue_index = n % len(component_statuses)
        component_statuses[issue_index]["status"] = "Warning"
        component_statuses[issue_index]["badge"] = "warning"
    
    for comp in component_statuses:
        components.append(html.Tr([
            html.Td(comp["name"]),
            html.Td(html.Span(comp["status"], className=f"badge bg-{comp['badge']}"))
        ]))
    
    return (
        overview,
        agent_status,
        status_class,
        hostname,
        ip_address,
        platform_str,
        uptime_str,
        cpu_percent,
        cpu_color,
        memory_percent,
        memory_color,
        disk_percent,
        disk_color,
        network_str,
        components
    )

# Callback for CPU history chart
@app.callback(
    [Output("cpu-history", "data"),
     Output("cpu-chart", "figure")],
    [Input("medium-interval", "n_intervals")],
    [State("cpu-history", "data")]
)
def update_cpu_history(n, current_history):
    # Get current CPU usage
    cpu_percent = psutil.cpu_percent()
    
    # Update history data
    history = current_history or []
    timestamp = datetime.now().strftime("%H:%M:%S")
    
    # Add new data point
    history.append({"time": timestamp, "value": cpu_percent})
    
    # Keep last 60 points (5 minutes with 5-second updates)
    if len(history) > 60:
        history = history[-60:]
    
    # Create the chart
    fig = px.line(
        history, 
        x="time", 
        y="value",
        labels={"time": "Time", "value": "CPU Usage (%)"},
        template="plotly_dark"
    )
    
    fig.update_layout(
        margin=dict(l=0, r=0, t=5, b=0),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(20,20,30,0.3)",
        xaxis=dict(showgrid=True, gridcolor="rgba(255,255,255,0.1)"),
        yaxis=dict(showgrid=True, gridcolor="rgba(255,255,255,0.1)", range=[0, 100]),
        font=dict(color="white"),
        showlegend=False
    )
    
    # Add shaded areas for thresholds
    fig.add_hrect(y0=70, y1=90, line_width=0, fillcolor="orange", opacity=0.1)
    fig.add_hrect(y0=90, y1=100, line_width=0, fillcolor="red", opacity=0.1)
    
    return history, fig

# Callback for Memory history chart
@app.callback(
    [Output("memory-history", "data"),
     Output("memory-chart", "figure")],
    [Input("medium-interval", "n_intervals")],
    [State("memory-history", "data")]
)
def update_memory_history(n, current_history):
    # Get current memory usage
    memory = psutil.virtual_memory()
    memory_percent = memory.percent
    
    # Update history data
    history = current_history or []
    timestamp = datetime.now().strftime("%H:%M:%S")
    
    # Add new data point
    history.append({"time": timestamp, "value": memory_percent})
    
    # Keep last 60 points
    if len(history) > 60:
        history = history[-60:]
    
    # Create the chart
    fig = px.line(
        history, 
        x="time", 
        y="value",
        labels={"time": "Time", "value": "Memory Usage (%)"},
        template="plotly_dark"
    )
    
    fig.update_layout(
        margin=dict(l=0, r=0, t=5, b=0),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(20,20,30,0.3)",
        xaxis=dict(showgrid=True, gridcolor="rgba(255,255,255,0.1)"),
        yaxis=dict(showgrid=True, gridcolor="rgba(255,255,255,0.1)", range=[0, 100]),
        font=dict(color="white"),
        showlegend=False
    )
    
    # Add shaded areas for thresholds
    fig.add_hrect(y0=70, y1=90, line_width=0, fillcolor="orange", opacity=0.1)
    fig.add_hrect(y0=90, y1=100, line_width=0, fillcolor="red", opacity=0.1)
    
    return history, fig

# Callback for recent logs
@app.callback(
    Output("recent-logs", "children"),
    Input("medium-interval", "n_intervals")
)
def update_logs(n):
    # Generate some simulated log entries
    log_levels = ["INFO", "WARNING", "ERROR", "DEBUG"]
    log_components = ["DetectionEngine", "ResponseManager", "Analytics", "NetworkMonitor", "APIServer"]
    
    log_templates = [
        "Started {component}",
        "Processing network traffic data",
        "Detected anomaly in traffic pattern",
        "Blocked suspicious connection from {ip}",
        "Performing system health check",
        "Resource usage above threshold: {resource}",
        "Successfully updated threat signatures",
        "Failed to connect to {service}",
        "New host discovered on network: {ip}",
        "Authentication attempt from {ip}"
    ]
    
    # Generate random IPs and resources
    ips = [f"192.168.1.{random.randint(2, 254)}" for _ in range(5)]
    resources = ["CPU", "Memory", "Disk", "Network"]
    services = ["API Server", "Update Service", "Cloud Service", "Database"]
    
    logs = []
    num_logs = min(10, n % 50 + 5)  # Between 5-15 logs
    
    for i in range(num_logs):
        # Time with decreasing recency
        minutes_ago = i * random.randint(1, 5)
        log_time = (datetime.now() - timedelta(minutes=minutes_ago)).strftime("%H:%M:%S")
        
        # Select message template and format it
        template = random.choice(log_templates)
        level = random.choice(log_levels)
        component = random.choice(log_components)
        
        # Apply formatting
        message = template.format(
            component=component,
            ip=random.choice(ips),
            resource=random.choice(resources),
            service=random.choice(services)
        )
        
        # Create level badge with appropriate color
        if level == "ERROR":
            level_badge = html.Span(level, className="badge bg-danger")
        elif level == "WARNING":
            level_badge = html.Span(level, className="badge bg-warning")
        elif level == "INFO":
            level_badge = html.Span(level, className="badge bg-primary")
        else:  # DEBUG
            level_badge = html.Span(level, className="badge bg-secondary")
            
        # Add log entry
        logs.append(
            html.Div([
                html.Span(f"[{log_time}] ", className="log-time"),
                level_badge,
                html.Span(f" [{component}] ", className="log-component"),
                html.Span(message, className="log-message")
            ], className="log-entry")
        )
    
    return logs

# Callback for action buttons
@app.callback(
    Output("action-feedback", "children"),
    [
        Input("restart-button", "n_clicks"),
        Input("stop-button", "n_clicks"),
        Input("diagnostic-button", "n_clicks"),
        Input("refresh-button", "n_clicks")
    ],
    [State("action-feedback", "children")]
)
def handle_actions(restart_clicks, stop_clicks, diag_clicks, refresh_clicks, current_feedback):
    ctx = dash.callback_context
    
    if not ctx.triggered:
        return ""
    
    button_id = ctx.triggered[0]["prop_id"].split(".")[0]
    action_time = datetime.now().strftime("%H:%M:%S")
    
    if button_id == "restart-button" and restart_clicks:
        return html.Div([
            html.I(className="fas fa-sync-alt me-2"),
            f"Restart initiated at {action_time}. Agent restarting..."
        ], className="alert alert-warning")
    elif button_id == "stop-button" and stop_clicks:
        return html.Div([
            html.I(className="fas fa-stop-circle me-2"),
            f"Stop initiated at {action_time}. Agent shutting down..."
        ], className="alert alert-danger")
    elif button_id == "diagnostic-button" and diag_clicks:
        return html.Div([
            html.I(className="fas fa-stethoscope me-2"),
            f"Diagnostic scan started at {action_time}. Running tests..."
        ], className="alert alert-info")
    elif button_id == "refresh-button" and refresh_clicks:
        return html.Div([
            html.I(className="fas fa-check-circle me-2"),
            f"Data refreshed at {action_time}."
        ], className="alert alert-success")
    
    return current_feedback

# Run the server if executed directly
if __name__ == "__main__":
    app.run(debug=True, port=8051)
