import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
import os

def generate_firewall_report(excel_file, output_pdf):
    elements = []  # Initialize elements HERE! (Moved to the beginning of the function)
    try:
        # Load the Excel file and extract "Findings" sheet
        df = pd.read_excel(excel_file, sheet_name="Findings")

        # Ensure the "Count" column is numeric
        df["Count"] = pd.to_numeric(df["Count"], errors="coerce").fillna(0)

        # Add Logo (Optional: Use your logo file)
        logo_path = "ecode_logo.png"  # Replace with the actual logo file path
        try:
            elements.append(Image(logo_path, width=200, height=100))
            elements.append(Spacer(1, 12)) # Add some space below the logo
        except FileNotFoundError:  # More specific exception handling
            print(f"Logo file not found: {logo_path}")
        except Exception as e: # Catch other exceptions during logo loading
            print(f"Error loading logo: {e}")

        # Create a PDF file
        doc = SimpleDocTemplate(output_pdf, pagesize=A4)
        styles = getSampleStyleSheet()

        # Title
        elements.append(Paragraph("Firewall Configuration Analysis Report", styles['Title']))
        elements.append(Paragraph(f"Date of Generation: {pd.Timestamp.now().strftime('%Y-%m-%d')}", styles['Normal']))
        elements.append(Paragraph(f"Uploaded File Name: {excel_file.split('/')[-1]}", styles['Normal']))
        elements.append(Spacer(1, 20))

        # Summary
        elements.append(Paragraph("<b>Summary</b>", styles['Heading2']))
        total_findings = len(df)
        severity_counts = df["Priority"].value_counts()
        summary_data = [
            ["Total Findings", total_findings],
            ["High Priority Issues", severity_counts.get("High", 0)],
            ["Medium Priority Issues", severity_counts.get("Medium", 0)],
            ["Low Priority Issues", severity_counts.get("Low", 0)],
            ["Informational Findings", severity_counts.get("Info", 0)],
        ]
        summary_table = Table(summary_data, colWidths=[200, 100])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 20))

        # Calculate Metrics
        total_address_objects = df[df["Category"] == "Addresses"]["Count"].sum()
        unused_address_objects = df[df["Title"].str.contains("Unused", case=False, na=False)]["Count"].sum()
        duplicate_address_objects = df[df["Title"].str.contains("Duplicate", case=False, na=False)]["Count"].sum()
        total_rules = df[df["Category"] == "Rules"]["Count"].sum()
        unused_rules = df[(df["Category"] == "Rules") & (df["Title"].str.contains("Unused", case=False, na=False))]["Count"].sum()
        high_risk_configs = df[df["Priority"] == "High"]["Count"].sum()
        redundant_rules = df[df["Title"].str.contains("Redundant", case=False, na=False)]["Count"].sum()

        # Key Issues Table
        elements.append(Paragraph("<b>Key Issues (High & Medium Priority)</b>", styles['Heading2']))
        key_issues = df[df["Priority"].isin(["High", "Medium"])][["Category", "Title", "Priority"]]

        if not key_issues.empty:
            key_issues_data = [["Category", "Title", "Priority"]] + key_issues.values.tolist()
            key_issues_table = Table(key_issues_data, colWidths=[150, 250, 100])
            key_issues_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            elements.append(key_issues_table)
        else:
            elements.append(Paragraph("No High or Medium Priority issues found.", styles['Normal']))
        elements.append(Spacer(1, 20))

        # Generate Graphs
        def generate_graphs():
            # Pie Chart for Severity Distribution
            severity_counts = df["Priority"].value_counts()  # Calculate counts inside the function
            if not severity_counts.empty: # Check if there is data to plot
                plt.figure(figsize=(5,5)) # Adjust figure size for better quality
                severity_counts.plot(kind='pie', autopct='%1.1f%%', colors=['green', 'orange', 'yellow', 'red'])
                plt.title("Severity Distribution")
                plt.savefig("severity_pie_chart.png", dpi=300) # Increase DPI for better resolution
                plt.close()
            else:
                print("No severity data to plot")

            # Bar Chart for Category Distribution
            category_counts = df["Category"].value_counts() # Calculate counts inside the function
            if not category_counts.empty: # Check if there is data to plot
                plt.figure(figsize=(8,6)) # Adjust figure size for better quality
                category_counts.plot(kind='bar', color='blue')
                plt.title("Findings by Category")
                plt.xlabel("Category")
                plt.ylabel("Count")
                plt.xticks(rotation=45, ha='right') # Rotate x-axis labels if needed
                plt.tight_layout() # Adjust layout to prevent labels from overlapping
                plt.savefig("category_bar_chart.png", dpi=300) # Increase DPI for better resolution
                plt.close()
            else:
                print("No category data to plot")

            # Stacked Bar Chart for Used vs Unused Objects
            used_vs_unused = {
                "Used": [total_address_objects - unused_address_objects if total_address_objects else 0], # Handle zero division
                "Unused": [unused_address_objects if total_address_objects else 0] # Handle zero division
            }
            if total_address_objects > 0: # Check if there are address objects to plot
                plt.figure(figsize=(6,6)) # Adjust figure size for better quality
                pd.DataFrame(used_vs_unused).plot(kind='bar', stacked=True, color=['green', 'red'])
                plt.title("Used vs Unused Address Objects")
                plt.ylabel("Count")
                plt.savefig("stacked_bar_chart.png", dpi=300) # Increase DPI for better resolution
                plt.close()
            else:
                print("No address object data to plot")

        generate_graphs()

        # Embed Graphs into PDF
        elements.append(Paragraph("<b>Visualizations</b>", styles['Heading2']))
        for img in ["severity_pie_chart.png", "category_bar_chart.png", "stacked_bar_chart.png"]:
            if os.path.exists(img): # Check if the image file exists
                elements.append(Image(img, width=400, height=300))
                elements.append(Spacer(1, 20))
            else:
                print(f"Image not found: {img}")

        # Unused & Duplicate Configurations
        elements.append(Paragraph("<b>Unused & Duplicate Configurations</b>", styles['Heading2']))

        # Unused Objects Table
        elements.append(Paragraph("<b>Unused Objects</b>", styles['Heading3']))
        unused_objects = df[df["Title"].str.contains("Unused", case=False, na=False)]

        if not unused_objects.empty:
            unused_objects_data = [["Category", "Title", "Count"]] + unused_objects[["Category", "Title", "Count"]].values.tolist()
            unused_objects_table = Table(unused_objects_data, colWidths=[150, 250, 100])
            unused_objects_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.orange),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            elements.append(unused_objects_table)
        else:
            elements.append(Paragraph("No unused objects found.", styles['Normal']))
        elements.append(Spacer(1, 20))

        # Duplicate Objects Table
        elements.append(Paragraph("<b>Duplicate Objects</b>", styles['Heading3']))
        duplicate_objects = df[df["Title"].str.contains("Duplicate", case=False, na=False)]

        if not duplicate_objects.empty:
            duplicate_objects_data = [["Category", "Title", "Count"]] + duplicate_objects[["Category", "Title", "Count"]].values.tolist()
            duplicate_objects_table = Table(duplicate_objects_data, colWidths=[150, 250, 100])
            duplicate_objects_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.green),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            elements.append(duplicate_objects_table)
        else:
            elements.append(Paragraph("No duplicate objects found.", styles['Normal']))
        elements.append(Spacer(1, 20))

        # Recommendations
        elements.append(Paragraph("<b>Recommendations</b>", styles['Heading2']))
        recommendations = [
            "✔ Remove or optimize unused address objects to improve efficiency.",
            "✔ Reduce duplicate configurations to minimize complexity.",
            "✔ Review high-priority issues and mitigate security risks immediately.",
            "✔ Ensure firewall rules follow industry best practices."
        ]
        for rec in recommendations:
            elements.append(Paragraph(rec, styles['Normal']))

        # Conclusion
        elements.append(Paragraph("<b>Conclusion</b>", styles['Heading2']))
        elements.append(Paragraph(
            "This report provides an analysis of firewall configurations, identifying key issues and areas for improvement. "
            "Immediate action on high-priority findings is recommended to enhance security posture and compliance.",
            styles['Normal']
        ))

        # Build PDF
        doc.build(elements)
        print(f"PDF report generated successfully: {output_pdf}")

    except Exception as e:
        print(f"Error generating PDF: {e}")

# Example Usage:
generate_firewall_report("randomized_config_20250205_1735_report.xlsx", "Firewall_Report_v0.04.pdf")
