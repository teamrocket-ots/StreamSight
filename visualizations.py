import plotly.express as px
import plotly.graph_objects as go
import numpy as np

def hist_with_boundaries(df, xcol, title, color="royalblue"):
    """
    Create a histogram with improved visual boundaries and statistical annotations.
    Returns None if the DataFrame is empty or the specified column is missing.
    """
    # Check for empty dataframe or missing column
    if df.empty or xcol not in df.columns:
        return None

    # Drop NaN values for calculation safety
    data = df[xcol].dropna()
    if data.empty:
        return None

    # Calculate optimal bin count using the Freedman-Diaconis rule
    try:
        q75, q25 = np.percentile(data, [75, 25])
    except Exception:
        return None
    iqr = q75 - q25
    bin_width = 2 * iqr / (len(data) ** (1/3)) if iqr > 0 else 0.01
    bin_count = int(np.ceil((data.max() - data.min()) / bin_width))
    bin_count = max(10, min(30, bin_count))  # Keep between 10 and 30 bins

    fig = px.histogram(
        df, 
        x=xcol, 
        nbins=bin_count, 
        title=title, 
        labels={xcol: "Delay (s)"},
        color_discrete_sequence=[color]
    )
    
    # Enhance bar visibility with borders
    fig.update_traces(
        marker=dict(
            line=dict(color='rgba(0, 0, 0, 0.5)', width=1)
        ),
        opacity=0.8
    )
    
    # Calculate basic statistics
    mean_val = data.mean()
    std_val = data.std()
    median_val = data.median()
    
    # Add vertical lines for mean and median
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
    
    # Add a shaded area representing ±1 standard deviation
    fig.add_vrect(
        x0=mean_val - std_val, 
        x1=mean_val + std_val, 
        fillcolor="rgba(0, 100, 80, 0.2)", 
        opacity=0.4, 
        line_width=0,
        annotation_text=f"±1σ: {std_val:.3f}s", 
        annotation_position="bottom right"
    )
    
    # Update layout for overall appearance
    fig.update_layout(
        bargap=0.1,
        plot_bgcolor='rgba(240, 240, 240, 0.8)',
        xaxis=dict(showgrid=True, gridcolor='rgba(200, 200, 200, 0.2)'),
        yaxis=dict(showgrid=True, gridcolor='rgba(200, 200, 200, 0.2)')
    )
    
    return fig
