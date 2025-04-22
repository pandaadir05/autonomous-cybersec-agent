"""
Generate a shield logo for the dashboard.
Run this script to create the shield-logo.png file.
"""

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import Path, PathPatch
import os

def create_shield_logo():
    # Create a shield shape
    def shield_path():
        verts = [
            (0.5, 0.0),    # Top point
            (1.0, 0.2),    # Top right
            (1.0, 0.6),    # Middle right
            (0.5, 1.0),    # Bottom point
            (0.0, 0.6),    # Middle left
            (0.0, 0.2),    # Top left
            (0.5, 0.0),    # Close path
        ]
        codes = [Path.MOVETO] + [Path.LINETO] * 5 + [Path.CLOSEPOLY]
        return Path(verts, codes)

    # Create the figure
    fig = plt.figure(figsize=(6, 6), facecolor='none')
    ax = fig.add_subplot(111)

    # Draw the shield
    shield = shield_path()
    shield_patch = PathPatch(shield, facecolor='#1a1a2e', edgecolor='#0f3460', linewidth=8)
    ax.add_patch(shield_patch)

    # Add a cyber pattern overlay
    x = np.linspace(0, 1, 100)
    y = np.linspace(0, 1, 100)
    X, Y = np.meshgrid(x, y)
    Z = 0.5 * np.sin(X * 15) * np.sin(Y * 15)

    # Create a mask in shield shape
    shield_mask = shield.contains_points(np.vstack([X.ravel(), Y.ravel()]).T).reshape(X.shape)
    Z = np.ma.masked_array(Z, mask=~shield_mask)

    # Plot the pattern
    ax.contourf(X, Y, Z, levels=20, cmap='Blues_r', alpha=0.4)
    ax.contour(X, Y, Z, levels=10, colors='#4361ee', linewidths=0.5, alpha=0.6)

    # Add a central "L" logo
    ax.text(0.5, 0.45, "L", fontsize=120, color='#4cc9f0', 
           family='monospace', weight='bold', ha='center', va='center')

    # Remove axes
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.set_aspect('equal')
    ax.axis('off')

    # Save with transparent background
    plt.tight_layout()
    save_path = os.path.join(os.path.dirname(__file__), "shield-logo.png")
    plt.savefig(save_path, dpi=300, transparent=True, bbox_inches='tight', pad_inches=0.1)
    plt.close()
    
    print(f"Shield logo created at: {save_path}")
    return save_path

if __name__ == "__main__":
    create_shield_logo()
