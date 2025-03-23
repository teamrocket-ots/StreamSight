import plotly.express as px
import plotly.graph_objects as go
import numpy as np
import pandas as pd

def hist_with_boundaries(df, xcol, title, color="royalblue"):
    """
    Create a histogram with better visual boundaries and statistical annotations.
    """
    if xcol not in df.columns or df[xcol].empty:
        fig = go.Figure()
        fig.update_layout(title=f"No data available for {xcol}")
        return fig
    
    # Calculate optimal bin count using Freedman-Diaconis rule
    q75, q25 = np.percentile(df[xcol], [75, 25])
    iqr = q75 - q25
    bin_width = 2 * iqr / (len(df) ** (1/3)) if iqr > 0 else 0.01
    bin_count = int(np.ceil((df[xcol].max() - df[xcol].min()) / bin_width))
    bin_count = max(10, min(30, bin_count))  # Keep between 10-30 bins
    
    fig = px.histogram(
        df,
        x=xcol,
        nbins=bin_count,
        title=title,
        labels={xcol: "Delay (s)"},
        color_discrete_sequence=[color]
    )
    
    # Add clear visual distinction to bars
    fig.update_traces(
        marker=dict(
            line=dict(color='rgba(0, 0, 0, 0.5)', width=1)
        ),
        opacity=0.8
    )
    
    # Calculate statistics
    mean_val = df[xcol].mean()
    std_val = df[xcol].std()
    median_val = df[xcol].median()
    
    # Add more visible annotations
    fig.add_vline(
        x=mean_val,
        line_width=2,
        line_dash="dash",
        line_color="red",
        annotation_text=f"Mean: {mean_val:.3f}s",
        annotation_position="top right",
        annotation_font=dict(size=12)
    )
    
    fig.add_vline(
        x=median_val,
        line_width=2,
        line_dash="dot",
        line_color="green",
        annotation_text=f"Median: {median_val:.3f}s",
        annotation_position="top left",
        annotation_font=dict(size=12)
    )
    
    # Make standard deviation range more visible
    fig.add_vrect(
        x0=mean_val-std_val,
        x1=mean_val+std_val,
        fillcolor="rgba(0, 100, 80, 0.2)",
        opacity=0.4,
        line_width=0,
        annotation_text=f"±1σ: {std_val:.3f}s",
        annotation_position="bottom right"
    )
    
    # Improve overall appearance
    fig.update_layout(
        bargap=0.1,  # Gap between bars
        plot_bgcolor='rgba(240, 240, 240, 0.8)',
        xaxis=dict(showgrid=True, gridcolor='rgba(200, 200, 200, 0.2)'),
        yaxis=dict(showgrid=True, gridcolor='rgba(200, 200, 200, 0.2)')
    )
    
    return fig

def tcp_delay_distribution(df_tcp, delay_type, title=None):
    """Create a histogram for TCP delay metrics with statistical annotations"""
    if df_tcp.empty or delay_type not in df_tcp.columns:
        fig = go.Figure()
        fig.update_layout(title=f"No data available for {delay_type}")
        return fig
    
    if title is None:
        title = f"TCP {delay_type.replace('_', ' ').title()} Distribution"
    
    return hist_with_boundaries(df_tcp, delay_type, title, color="blue")

def udp_jitter_plot(df_udp):
    """Create a scatter plot showing the relationship between jitter and packet loss"""
    if df_udp.empty or not all(col in df_udp.columns for col in ['jitter', 'possible_loss']):
        fig = go.Figure()
        fig.update_layout(title="No UDP jitter or packet loss data available")
        return fig
    
    fig = px.scatter(
        df_udp,
        x="jitter",
        y="possible_loss",
        size="payload_size" if "payload_size" in df_udp.columns else None,
        color="congestion_level" if "congestion_level" in df_udp.columns else None,
        hover_data=["timestamp", "conn_id"],
        title="UDP Jitter vs Packet Loss Analysis",
        labels={
            "jitter": "Jitter (s)",
            "possible_loss": "Estimated Packet Loss",
            "payload_size": "Payload Size"
        }
    )
    
    # Improve appearance
    fig.update_layout(
        plot_bgcolor='rgba(240, 240, 240, 0.8)',
        xaxis=dict(showgrid=True, gridcolor='rgba(200, 200, 200, 0.2)'),
        yaxis=dict(showgrid=True, gridcolor='rgba(200, 200, 200, 0.2)')
    )
    
    return fig

def mqtt_delay_components(df_mqtt):
    """Create a stacked bar chart showing the components of MQTT delay"""
    if df_mqtt.empty:
        fig = go.Figure()
        fig.update_layout(title="No MQTT delay data available")
        return fig
    
    # Prepare data for visualization
    components = []
    for delay_type in ['device_to_broker_delay', 'broker_processing_delay', 'cloud_upload_delay']:
        if delay_type in df_mqtt.columns:
            values = df_mqtt[delay_type].dropna()
            if not values.empty:
                components.append({
                    'component': delay_type.replace('_', ' ').title(),
                    'mean': values.mean(),
                    'median': values.median(),
                    'p95': values.quantile(0.95)
                })
    
    if not components:
        fig = go.Figure()
        fig.update_layout(title="No MQTT delay components available")
        return fig
    
    df_components = pd.DataFrame(components)
    
    # Create grouped bar chart
    fig = go.Figure()
    
    fig.add_trace(go.Bar(
        x=df_components['component'],
        y=df_components['mean'],
        name='Mean',
        marker_color='rgb(55, 83, 109)'
    ))
    
    fig.add_trace(go.Bar(
        x=df_components['component'],
        y=df_components['median'],
        name='Median',
        marker_color='rgb(26, 118, 255)'
    ))
    
    fig.add_trace(go.Bar(
        x=df_components['component'],
        y=df_components['p95'],
        name='95th Percentile',
        marker_color='rgb(246, 78, 139)'
    ))
    
    fig.update_layout(
        title="MQTT Delay Components",
        xaxis_title="Delay Component",
        yaxis_title="Time (s)",
        barmode='group',
        bargap=0.15,
        bargroupgap=0.1
    )
    
    return fig

def connection_rtt_chart(df_tcp):
    """Create a bar chart of RTT by connection"""
    if df_tcp.empty or 'rtt' not in df_tcp.columns or 'conn_id' not in df_tcp.columns:
        fig = go.Figure()
        fig.update_layout(title="No RTT data available")
        return fig
    
    # Group by connection and calculate mean RTT
    rtt_by_conn = df_tcp.groupby('conn_id')['rtt'].mean().reset_index()
    
    # Sort by RTT and take top 10
    top_conns = rtt_by_conn.sort_values('rtt', ascending=False).head(10)
    
    fig = px.bar(
        top_conns,
        x='conn_id',
        y='rtt',
        title="Top 10 Connections by RTT",
        labels={
            'conn_id': 'Connection',
            'rtt': 'RTT (s)'
        }
    )
    
    fig.update_layout(
        xaxis={'tickangle': 45},
        plot_bgcolor='rgba(240, 240, 240, 0.8)'
    )
    
    return fig

def congestion_heatmap(df_udp):
    """Create a heatmap showing congestion scores over time"""
    if df_udp.empty or 'congestion_score' not in df_udp.columns:
        fig = go.Figure()
        fig.update_layout(title="No congestion data available")
        return fig
    
    # Sample the data to avoid overcrowding (if needed)
    if len(df_udp) > 500:
        df_udp = df_udp.sample(500)
    
    # Group by timestamp (rounded to nearest second) and connection
    df_udp['time_rounded'] = pd.to_datetime(df_udp['timestamp'], unit='s').dt.round('1s')
    
    # Get unique connections
    connections = df_udp['conn_id'].unique()
    
    # Create heatmap data
    heatmap_data = []
    for conn in connections:
        conn_data = df_udp[df_udp['conn_id'] == conn]
        for _, row in conn_data.iterrows():
            heatmap_data.append({
                'time': row['time_rounded'],
                'connection': conn,
                'congestion': row['congestion_score'] if 'congestion_score' in row else 0
            })
    
    if not heatmap_data:
        fig = go.Figure()
        fig.update_layout(title="No congestion data available for heatmap")
        return fig
    
    df_heatmap = pd.DataFrame(heatmap_data)
    
    fig = px.density_heatmap(
        df_heatmap,
        x='time',
        y='connection',
        z='congestion',
        title="Connection Congestion Over Time",
        labels={
            'time': 'Time',
            'connection': 'Connection',
            'congestion': 'Congestion Score'
        }
    )
    
    fig.update_layout(
        xaxis={'title': 'Time'},
        yaxis={'title': 'Connection'},
        coloraxis_colorbar={'title': 'Congestion Score'}
    )
    
    return fig
