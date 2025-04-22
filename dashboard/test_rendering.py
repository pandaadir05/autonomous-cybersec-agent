"""
Test script to verify dashboard rendering is working correctly.
This creates a simple dashboard with test charts to ensure all visualizations render properly.
"""

import dash
from dash import html, dcc
import dash_bootstrap_components as dbc
import plotly.express as px
import plotly.graph_objects as go
import numpy as np
import pandas as pd

# Create test app
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.CYBORG])

# Create test data
np.random.seed(42)
df = pd.DataFrame({
    'x': range(10),
    'y1': np.random.rand(10) * 10,
    'y2': np.random.rand(10) * 10,
    'size': np.random.rand(10) * 10
})

# Create test charts
line_fig = px.line(df, x='x', y='y1', title='Test Line Chart')
bar_fig = px.bar(df, x='x', y='y2', title='Test Bar Chart')
scatter_fig = px.scatter(df, x='y1', y='y2', size='size', title='Test Scatter Plot')

# Create a 3D chart
z = np.outer(
    np.sin(np.linspace(0, 2*np.pi, 30)),
    np.sin(np.linspace(0, 2*np.pi, 30))
)
surface_fig = go.Figure(data=[go.Surface(z=z)])
surface_fig.update_layout(title='Test 3D Surface Plot', autosize=True)

# Create layout
app.layout = dbc.Container([
    html.H1("Dashboard Rendering Test", className="my-4 text-center"),
    
    html.P("This page tests whether charts render correctly on your setup.", className="lead text-center mb-4"),
    
    # 2D charts row
    dbc.Row([
        dbc.Col(dcc.Graph(figure=line_fig), width=6),
        dbc.Col(dcc.Graph(figure=bar_fig), width=6)
    ], className="mb-4"),
    
    # 3D chart and scatter
    dbc.Row([
        dbc.Col(dcc.Graph(figure=surface_fig), width=6),
        dbc.Col(dcc.Graph(figure=scatter_fig), width=6)
    ], className="mb-4"),
    
    # Test card with metrics
    dbc.Card([
        dbc.CardHeader("Test Metrics"),
        dbc.CardBody([
            dbc.Row([
                dbc.Col([
                    html.H3("42", className="metric-value text-center"),
                    html.P("Test Value 1", className="text-center")
                ]),
                dbc.Col([
                    html.H3("78%", className="metric-value text-center"),
                    html.P("Test Value 2", className="text-center")
                ])
            ])
        ])
    ], className="mb-4"),
    
    dbc.Alert("If you can see all charts and metrics above with proper colors and contrast, rendering is working correctly!", color="success"),
    
    html.Footer([
        html.P("Dashboard rendering test completed successfully if all elements are visible.", className="text-center text-muted mt-4")
    ])
], fluid=True, style={"backgroundColor": "#121212"})

# Run the app
if __name__ == "__main__":
    app.run(debug=True, port=8051)
