import plotly.express as px
import plotly.graph_objects as go
import numpy as np

def hist_with_boundaries(df, xcol, title, color="royalblue"):
    """
    Create a histogram with better visual boundaries and statistical annotations.
    """
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