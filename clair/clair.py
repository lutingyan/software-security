import subprocess
import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from fpdf import FPDF
import re

def sanitize_image_name(image_name):
    """
    Sanitize the image name for safe usage in file names.
    :param image_name: Docker image name (e.g., 'kennethreitz/httpbin').
    :return: Sanitized image name.
    """
    sanitized_name = re.sub(r'[^\w\-]', '_', image_name)  # Replace non-alphanumeric characters with '_'
    return sanitized_name


def pull_docker_image(image_name):
    """
    Pull a Docker image from Docker Hub (or other registry).
    :param image_name: Name of the Docker image to pull (e.g., "mysql:5.7").
    """
    try:
        # Run Docker pull command
        print(f"Pulling Docker image: {image_name}...")
        command = ["docker", "pull", image_name]
        subprocess.run(command, check=True)
        print(f"Image {image_name} pulled successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error pulling image {image_name}: {e.stderr.decode('utf-8') if e.stderr else 'No error message'}")
        raise
    except FileNotFoundError:
        print("Docker is not installed. Please install Docker and try again.")
        raise
    except Exception as e:
        print(f"An unexpected error occurred while pulling the image: {e}")
        raise


def scan_with_clair(image_name, output_file="clair_report.json"):
    """
    Scan a Docker image for vulnerabilities using Clair and save the result as a JSON file.
    :param image_name: Name of the Docker image to scan (e.g., "mysql:5.7").
    :param output_file: Path to save the scan results in JSON format.
    """
    # Pull the Docker image first
    pull_docker_image(image_name)

    # Run Clair scanner command and save output to JSON
    command = [
        "clair-scanner",
        "-c", "http://172.17.0.1:6060",
        "--ip", "172.17.0.1",
        "--report", output_file,
        image_name
    ]
    print(f"Scanning image: {image_name} using Clair...")

    # Run the Clair scan and capture output for debugging
    result = subprocess.run(command, capture_output=True, text=True)

    return result


def process_results(results):
    """
    Process Clair results and convert them to a DataFrame.
    :param results: Parsed JSON results from Clair.
    :return: Processed DataFrame.
    """
    vulnerabilities = []

    # Print the structure of the results for debugging
    print("Processing results:")
    print(json.dumps(results, indent=4))  # This will print the JSON structure nicely

    # Iterate over the vulnerabilities list in the JSON structure
    for vulnerability in results.get("vulnerabilities", []):
        vulnerabilities.append({
            "Feature Name": vulnerability.get("featurename", "Unknown"),
            "Feature Version": vulnerability.get("featureversion", "Unknown"),
            "Vulnerability ID": vulnerability.get("vulnerability", "Unknown"),
            "Namespace": vulnerability.get("namespace", "Unknown"),
            "Severity": vulnerability.get("severity", "Unknown"),
            "Description": vulnerability.get("description", "No description"),
            "Fixed By": vulnerability.get("fixedby", "Not available"),
            "Link": vulnerability.get("link", "No link")
        })

    # If no vulnerabilities were found, return an empty DataFrame
    if not vulnerabilities:
        print("No vulnerabilities found!")
        return pd.DataFrame()

    # Convert the list of dictionaries to a DataFrame
    df = pd.DataFrame(vulnerabilities)
    print(f"\nVulnerabilities found:\n{df}")
    return df


def generate_visuals(vulnerability_df, image_name):
    """
    Generate visualizations from vulnerability data.
    :param vulnerability_df: Pandas DataFrame containing vulnerability data.
    :param image_name: Docker image name, used for chart titles.
    """
    sanitized_image_name = sanitize_image_name(image_name)
    sns.set(style="whitegrid")

    # Pie chart: Severity distribution
    plt.figure(figsize=(10, 6))
    severity_counts = vulnerability_df["Severity"].value_counts()
    severity_counts.plot(kind="pie", autopct='%1.1f%%', startangle=140)
    plt.title(f"Vulnerability Severity Distribution\nImage: {image_name}", fontsize=16, pad=20)
    plt.ylabel("")  # Remove default Y-axis label
    plt.savefig(f"{sanitized_image_name}_severity_pie_chart.png")
    plt.close()

    # Bar chart: Top affected features
    plt.figure(figsize=(10, 6))
    top_features = vulnerability_df["Feature Name"].value_counts().head(10)
    top_features.plot(kind="barh")
    plt.title(f"Top 10 Most Affected Features\nImage: {image_name}", fontsize=16, pad=20)
    plt.xlabel("Number of Vulnerabilities", fontsize=12, labelpad=10)
    plt.ylabel("Feature Name", fontsize=12, labelpad=10)
    plt.tight_layout()
    plt.savefig(f"{sanitized_image_name}_top_features_bar_chart.png")
    plt.close()


def generate_pdf_report(vulnerability_df, image_name, total_vulnerabilities, severity_distribution):
    """
    Generate a PDF report for the vulnerabilities.
    :param vulnerability_df: Pandas DataFrame containing vulnerability data.
    :param image_name: Docker image name, used in the report title.
    :param total_vulnerabilities: Total number of vulnerabilities found.
    :param severity_distribution: Dictionary of vulnerability severities and their counts.
    """
    sanitized_image_name = sanitize_image_name(image_name)

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Report title
    pdf.set_font("Arial", size=16, style="B")
    pdf.cell(200, 10, txt=f"Docker Image Scan Report: {image_name}", ln=True, align="C")
    pdf.ln(10)

    # Summary section
    pdf.set_font("Arial", size=12, style="B")
    pdf.cell(200, 10, txt="Scan Summary:", ln=True, align="L")
    pdf.set_font("Arial", size=10)
    pdf.cell(200, 10, txt=f"- Total vulnerabilities found: {total_vulnerabilities}", ln=True)
    pdf.cell(200, 10, txt="- Severity distribution:", ln=True)
    for severity, count in severity_distribution.items():
        pdf.cell(200, 10, txt=f"  * {severity}: {count}", ln=True)
    pdf.ln(10)

    # Vulnerability details
    pdf.set_font("Arial", size=12, style="B")
    pdf.cell(200, 10, txt="Vulnerability Details:", ln=True, align="L")
    pdf.set_font("Arial", size=10)
    for _, row in vulnerability_df.iterrows():
        pdf.cell(200, 10, txt=f"- {row['Severity']} | {row['Vulnerability ID']} | {row['Feature Name']} "
                              f"| Installed: {row['Feature Version']} "
                              f"| Fixed: {row['Fixed By']}", ln=True)

    # Add charts
    pdf.add_page()
    pdf.set_font("Arial", size=12, style="B")
    pdf.cell(200, 10, txt="Vulnerability Severity Distribution:", ln=True, align="L")
    pdf.image(f"{sanitized_image_name}_severity_pie_chart.png", x=10, y=30, w=180)

    pdf.add_page()
    pdf.cell(200, 10, txt="Top 10 Most Affected Features:", ln=True, align="L")
    pdf.image(f"{sanitized_image_name}_top_features_bar_chart.png", x=10, y=30, w=180)

    # Save PDF
    pdf.output(f"{sanitized_image_name}_clair_scan_report.pdf")
    print(f"PDF report generated: {sanitized_image_name}_clair_scan_report.pdf")


def main():
    # Image name for Docker scan
    image_name = "kennethreitz/httpbin"
    output_file = "clair_report.json"  # Path to save JSON results

    # Perform the scan and process results
    result = scan_with_clair(image_name, output_file)
    print(111)
    print(result.returncode)

    # Check if Clair scan ran successfully
    if result.returncode == 1:
        print(f"Scan completed successfully. Results saved to {output_file}")
        # Process the JSON output (you can extend this part to handle the data and generate reports)
        with open(output_file, "r") as f:
            results = json.load(f)
        # Process the results and generate visuals
        vulnerabilities = process_results(results)

        if not vulnerabilities.empty:
            total_vulnerabilities = len(vulnerabilities)
            severity_distribution = vulnerabilities["Severity"].value_counts().to_dict()

            # Generate visuals (graphs)
            generate_visuals(vulnerabilities, image_name)

            # Generate PDF report
            generate_pdf_report(vulnerabilities, image_name, total_vulnerabilities, severity_distribution)
    else:
        print(f"Clair scan failed with return code {result.returncode}. Error output: {result.stderr}")


# Run the script
if __name__ == "__main__":
    main()
