import subprocess
import json
import pandas as pd
import matplotlib.pyplot as plt
from fpdf import FPDF


def pull_docker_image(image_name):
    """
    Pull a Docker image from Docker Hub (or other registry).
    :param image_name: Name of the Docker image to pull (e.g., "nginx:latest").
    """
    try:
        # Run Docker pull command
        print(f"Pulling Docker image: {image_name}...")
        command = ["docker", "pull", image_name]
        subprocess.run(command, check=True)
        print(f"Image {image_name} pulled successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error pulling image {image_name}: {e.stderr.decode('utf-8')}")
        raise
    except FileNotFoundError:
        print("Docker is not installed. Please install Docker and try again.")
        raise
    except Exception as e:
        print(f"An unexpected error occurred while pulling the image: {e}")
        raise


def scan_docker_image(image_name="kennethreitz/httpbin", output_file="trivy_scan_results.json"):
    """
    Scan a Docker image for vulnerabilities using Trivy and generate a report.
    :param image_name: Name of the Docker image to scan.
    :param output_file: Path to save the scan results in JSON format.
    """
    try:
        # Pull the Docker image first
        pull_docker_image(image_name)

        # Run Trivy command and save output to JSON
        print(f"Scanning image: {image_name} using Trivy...")
        command = [
            "trivy", "image", "--severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
            "-f", "json", "-o", output_file, image_name
        ]
        subprocess.run(command, check=True)

        # Load and process results
        with open(output_file, "r") as f:
            results = json.load(f)

        vulnerabilities = process_results(results)

        if not vulnerabilities.empty:
            total_vulnerabilities = len(vulnerabilities)
            print(f"Total vulnerabilities found: {total_vulnerabilities}")
            severity_distribution = vulnerabilities["Severity"].value_counts().to_dict()
            print(f"Severity distribution: {severity_distribution}")

            generate_visuals(vulnerabilities, image_name)
            generate_pdf_report(vulnerabilities, image_name, total_vulnerabilities, severity_distribution)
        else:
            print("No vulnerabilities found.")

    except subprocess.CalledProcessError as e:
        print(f"Error running Trivy: {e}")
    except FileNotFoundError:
        print("Trivy is not installed. Please install Trivy and try again.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


def process_results(results):
    """
    Process Trivy results and convert them to a DataFrame.
    :param results: Parsed JSON results from Trivy.
    :return: Processed DataFrame.
    """
    vulnerabilities = []
    for result in results.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            # Safely get the 'Title' field, using a default value if it's missing
            description = vuln.get("Title", "No description available")

            vulnerabilities.append({
                "ID": vuln["VulnerabilityID"],
                "Severity": vuln["Severity"],
                "Package": vuln["PkgName"],
                "Installed Version": vuln["InstalledVersion"],
                "Fixed Version": vuln.get("FixedVersion", "Not available"),
                "Description": description
            })

    if not vulnerabilities:
        print("No vulnerabilities found!")
        return pd.DataFrame()

    df = pd.DataFrame(vulnerabilities)
    print(f"\nVulnerabilities found:\n{df}")
    return df


def generate_visuals(vulnerability_df, image_name):
    """
    Generate visualizations from vulnerability data.
    :param vulnerability_df: Pandas DataFrame containing vulnerability data.
    :param image_name: Docker image name, used for chart titles.
    """
    # Pie chart: Severity distribution
    plt.figure(figsize=(10, 6))
    severity_counts = vulnerability_df["Severity"].value_counts()
    severity_counts.plot(kind="pie", autopct='%1.1f%%', startangle=140)
    plt.title(f"Vulnerability Severity Distribution\nImage: {image_name}", fontsize=16, pad=20)
    plt.ylabel("")  # Remove default Y-axis label
    plt.savefig("trivy_severity_pie_chart.png")
    plt.close()

    # Bar chart: Top affected packages
    plt.figure(figsize=(10, 6))
    top_packages = vulnerability_df["Package"].value_counts().head(10)
    top_packages.plot(kind="barh")
    plt.title(f"Top 10 Most Affected Packages\nImage: {image_name}", fontsize=16, pad=20)
    plt.xlabel("Number of Vulnerabilities", fontsize=12, labelpad=10)
    plt.ylabel("Package Name", fontsize=12, labelpad=10)
    plt.tight_layout()
    plt.savefig("trivy_top_packages_bar_chart.png")
    plt.close()


def generate_pdf_report(vulnerability_df, image_name, total_vulnerabilities, severity_distribution):
    """
    Generate a PDF report for the vulnerabilities.
    :param vulnerability_df: Pandas DataFrame containing vulnerability data.
    :param image_name: Docker image name, used in the report title.
    :param total_vulnerabilities: Total number of vulnerabilities found.
    :param severity_distribution: Dictionary of vulnerability severities and their counts.
    """
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
        pdf.cell(200, 10, txt=f"- {row['Severity']} | {row['ID']} | {row['Package']} "
                              f"| Installed: {row['Installed Version']} "
                              f"| Fixed: {row['Fixed Version']}", ln=True)

    # Add charts
    pdf.add_page()
    pdf.set_font("Arial", size=12, style="B")
    pdf.cell(200, 10, txt="Vulnerability Severity Distribution:", ln=True, align="L")
    pdf.image("trivy_severity_pie_chart.png", x=10, y=30, w=180)

    pdf.add_page()
    pdf.cell(200, 10, txt="Top 10 Most Affected Packages:", ln=True, align="L")
    pdf.image("trivy_top_packages_bar_chart.png", x=10, y=30, w=180)

    # Save PDF
    pdf.output("trivy_scan_report.pdf")
    print("PDF report generated: trivy_scan_report.pdf")


# Example usage
if __name__ == "__main__":
    scan_docker_image()