import json
import sys
import re

def process_benchmark_data(data, output_html_file):
    entries = data.get("entries", {}).get("Rust Benchmark", [])
    if not entries:
        print("No 'Rust Benchmark' entries found.")
        return

    last_entry = entries[-1]  # Get the last entry
    last_benches = last_entry.get("benches", [])

    if not last_benches: # added check for empty benches list
        print("No benches data found in the last entry.")
        dkg_data = []
        dsg_data = []
    else:
        dkg_data = [item for item in last_benches if item["name"].startswith("dkg-")]
        dsg_data = [item for item in last_benches if item["name"].startswith("dsg-")]

    last_timestamp = last_entry.get("commit", {}).get("timestamp", "Timestamp not found")
    last_url = last_entry.get("commit", {}).get("url", "URL not found")

    def create_styled_table(data, table_name):
        if not data:
            return f"<p style='text-align: center; font-style: italic;'>No data for {table_name}.</p>"

        modified_data = [{"Setting": item["name"], "Time": item["value"] / 1000000} for item in data]

        keys = modified_data[0].keys()
        html = f"<h2 style='text-align: center; color: #3366cc;'>{table_name.upper()} Benchmarks (ms)</h2>\n"
        html += "<table style='width: 80%; margin: 20px auto; border-collapse: collapse; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);'>\n"
        html += "<thead style='background-color: #f0f8ff;'>\n"
        html += "<tr>\n"
        for key in keys:
            html += f"<th style='padding: 12px; text-align: left; border-bottom: 2px solid #ddd;'>{key}</th>\n"
        html += "</tr>\n"
        html += "</thead>\n"
        html += "<tbody>\n"
        for item in modified_data:
            html += "<tr>\n"
            for value in item.values():
                html += f"<td style='padding: 10px; border-bottom: 1px solid #eee;'>{value}</td>\n"
            html += "</tr>\n"
        html += "</tbody>\n"
        html += "</table>\n"
        return html

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
    <title>Latest Benchmark Results</title>
    <style>
        body {{ font-family: 'Arial', sans-serif; margin: 20px; }}
        .header {{ text-align: center; margin-bottom: 20px; }}
    </style>
    </head>
    <body>
    <div class="header">
        <p><strong>Last Timestamp:</strong> {last_timestamp}</p>
        <p><strong>Commit URL:</strong> <a href="{last_url}">{last_url}</a></p>
    </div>
    """

    html_content += create_styled_table(dkg_data, "DKLs23-KeyGen")
    html_content += create_styled_table(dsg_data, "DKLs23-Sign")

    html_content += """
    </body>
    </html>
    """

    with open(output_html_file, 'w') as f:
        f.write(html_content)

    print(f"HTML tables created and saved to {output_html_file}")

def parse_js_object(filename):
   
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            js_content = f.read().strip()

        # Use regex to find the object
        match = re.search(r'^\s*window\.BENCHMARK_DATA\s*=\s*({.*?});?$', js_content, re.DOTALL)
        if match:
            json_str = match.group(1)  # Extract the JSON-like string
        else:
            print(f"Error: Could not find JavaScript object in {filename}")
            return None

        # Parse the JSON string
        try:
            data = json.loads(json_str)
            return data
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON: {e}")
            return None

    except FileNotFoundError:
        print(f"Error: File not found: {filename}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <filename>")
        sys.exit(1)

    filename = sys.argv[1]
    parsed_data = parse_js_object(filename)

    if parsed_data:
        print(json.dumps(parsed_data, indent=2))
        process_benchmark_data(parsed_data, "index.html")
    else:
        sys.exit(1)

