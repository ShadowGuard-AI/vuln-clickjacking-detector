import argparse
import requests
import logging
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description='Detects Clickjacking vulnerability in a website.')
    parser.add_argument('url', type=str, help='The URL of the website to check.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output (debug logging).')
    return parser

def check_clickjacking(url):
    """
    Checks for clickjacking vulnerability by analyzing HTTP headers.
    
    Args:
        url (str): The URL of the website to check.
        
    Returns:
        tuple: (vulnerable (bool), headers (dict), messages (list))
    """
    try:
        # Sanitize URL (Basic input validation)
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url  # Default to HTTP if no protocol specified
        
        # Send a GET request to the URL. Error responses are analyzed too:
        # their framing headers are exactly what this tool exists to read.
        response = requests.get(url, timeout=10)

        headers = response.headers
        x_frame_options = headers.get('X-Frame-Options')
        content_security_policy = headers.get('Content-Security-Policy')
        
        # I start from vulnerable and let either header clear it on its own.
        # The two checks never put the flag back to True, so protection in
        # one header is not undone by a weak or missing second header.
        vulnerable = True
        messages = []
        
        if x_frame_options:
            messages.append(f"X-Frame-Options header found: {x_frame_options}")
            # Exact match after lowering, so a combined value or an
            # ALLOW-FROM value does not count as protection here. That is
            # deliberate: ALLOW-FROM is ignored by most current browsers.
            if x_frame_options.lower() in ['deny', 'sameorigin']:
                vulnerable = False
                messages.append("Website is likely protected against clickjacking by X-Frame-Options.")
        else:
            messages.append("X-Frame-Options header is missing.")
            
        if content_security_policy:
            messages.append(f"Content-Security-Policy header found: {content_security_policy}")
            frame_ancestors_values = None
            for directive in content_security_policy.split(';'):
                parts = directive.strip().split()
                if parts and parts[0].lower() == "frame-ancestors":
                    frame_ancestors_values = [p.lower() for p in parts[1:]]
                    # The break means the first frame-ancestors directive
                    # wins. A second one later in the header is never read,
                    # which matches how browsers take the first occurrence.
                    break

            if frame_ancestors_values is not None:
                # Protection only when the value restricts framing: 'none',
                # 'self', or named sources. A bare * permits anyone to frame.
                restricting = [v for v in frame_ancestors_values if v != "*"]
                if restricting:
                    vulnerable = False
                    messages.append("Website is likely protected against clickjacking by Content-Security-Policy frame-ancestors.")
                else:
                    messages.append("Content-Security-Policy frame-ancestors allows framing by any origin (*).")
            else:
                messages.append("Content-Security-Policy header does not appear to have clickjacking protection.")
        else:
            messages.append("Content-Security-Policy header is missing.")
        
        if vulnerable:
            messages.append("Website may be vulnerable to clickjacking.")
            messages.append("Mitigation: Implement X-Frame-Options or Content-Security-Policy to prevent framing.")
        
        return vulnerable, headers, messages
    except requests.exceptions.RequestException as e:
        logging.error(f"Request error: {e}")
        return None, {}, [f"Error during request: {e}"]  # Inconclusive: the target was not reached.
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")
        return None, {}, [f"An unexpected error occurred: {e}"]  # Inconclusive.

def main():
    """
    Main function to execute the clickjacking detection tool.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose mode enabled.")
    
    url = args.url

    if not url:
        print("Error: URL is required.")
        sys.exit(1)

    logging.info(f"Checking URL: {url}")
    vulnerable, headers, messages = check_clickjacking(url)
    
    print(f"Clickjacking Detection Results for {url}:")
    for message in messages:
        print(message)

    if vulnerable is None:
        print("\nINCONCLUSIVE: The target could not be reached, so no clickjacking verdict is available.")
        sys.exit(1)

    if vulnerable:
        print("\nWARNING: The website appears to be vulnerable to clickjacking!")
    else:
        print("\nThe website appears to be protected against clickjacking.")

    logging.info("Scan completed.")

if __name__ == "__main__":
    main()