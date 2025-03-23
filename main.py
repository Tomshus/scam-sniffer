import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox
from constants import PROJECT_ROOT, MODULE_DIR

# Add the project root and module directories to Python path
sys.path.extend([PROJECT_ROOT, MODULE_DIR])

from modules.extraction import extract_features
from modules.api_integration import (
    check_openphish,
    check_google_safe_browsing,
    check_virustotal,
)

def set_read_only(text_widget):
    text_widget.config(state="disabled")

def analyze_url_gui(url, result_text, progress_bar):
    """Analyze the URL and display results in the GUI."""
    result_text.config(state="normal")  # Allow writing temporarily
    result_text.delete(1.0, tk.END)  # Clear previous results
    result_text.insert(tk.END, f"🔍 Analyzing {url}...\n\n")
    progress_bar["value"] = 0  # Reset progress bar
    progress_bar.update()

    try:
        # Feature Extraction
        progress_bar["value"] = 20
        progress_bar.update()
        features = extract_features(url)
        formatted_features = "\n".join([f"{key}: {value}" for key, value in features.items()])
        result_text.insert(tk.END, f"📊 Extracted Features:\n{formatted_features}\n\n")

        # VirusTotal Check
        progress_bar["value"] = 50
        progress_bar.update()
        virustotal_result = check_virustotal(url)

        # OpenPhish Check
        progress_bar["value"] = 70
        progress_bar.update()
        openphish_result = check_openphish(url)

        # Google Safe Browsing Check
        progress_bar["value"] = 90
        progress_bar.update()
        google_result = check_google_safe_browsing(url)

        # Display results
        result_text.insert(tk.END, f"🔹 VirusTotal: {virustotal_result}\n")
        result_text.insert(tk.END, f"🔹 OpenPhish: {openphish_result}\n")
        result_text.insert(tk.END, f"🔹 Google Safe Browsing: {google_result}\n")
        result_text.insert(tk.END, "\n✅ Analysis completed.")
        progress_bar["value"] = 100  # Complete progress bar
        progress_bar.update()
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")
        progress_bar["value"] = 0  # Reset progress bar on error
        progress_bar.update()

    # Make the text box read-only after updating
    set_read_only(result_text)

def create_gui():
    """Create the GUI for the URL analysis tool."""
    root = tk.Tk()
    root.title("Scam Sniffer")

    # URL Input
    url_label = ttk.Label(root, text="Enter URL:")
    url_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")

    url_entry = ttk.Entry(root, width=80)
    url_entry.grid(row=0, column=1, padx=10, pady=10, sticky="w")

    # Progress Bar
    progress_bar = ttk.Progressbar(root, orient="horizontal", length=400, mode="determinate")
    progress_bar.grid(row=1, column=0, columnspan=2, padx=10, pady=10)

    # Result Text Box
    result_text = tk.Text(root, height=20, width=80, wrap="word", state="normal")  # Initially normal
    result_text.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

    # Analyze Button
    analyze_button = ttk.Button(
        root,
        text="Analyze",
        command=lambda: analyze_url_gui(url_entry.get(), result_text, progress_bar),
    )
    analyze_button.grid(row=2, column=0, columnspan=2, pady=10)

    # Start the GUI event loop
    root.mainloop()

if __name__ == "__main__":
    create_gui()
