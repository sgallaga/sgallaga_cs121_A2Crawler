import re
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

def log_error(message):
    # Logs any encountered errors to error_log.text
    with open(LOG_FILE, "a") as f:
        f.write(message + "\n")

def is_low_info():
    # Returns True if page is a low info page
    text = soup.get_text(separator=' ')
    total_words = text.split()

    # Installed heuristics to determine if low-info or not
    if len(words) < 50: # Too short
        return True

    links = len(soup.find_all('a'))
    if links > 100 and len(words) / links < 2: # Evaluate word to link ratio
        return True
    
    return False

def scraper(url, resp):
    #links = extract_next_links(url, resp)
    #return [link for link in links if is_valid(link)]
    
    # Check return status to be 200 (ok) and for a valid .raw_response
    if resp.status != 200 or not resp.raw_response:
        print(f"Skipping {url} due to bad response: {resp.status}") # Debugging
        return []

    # Extract text content from resp.raw_response.content using Beautiful soup
    html_con = resp.raw_response.content
    soup = BeautifulSoup(html_con, "html.parser")

    # Detect if page is low information
    if is_low_info(soup):
        return []
    
    # Extract all links from the page
    links = [urljoin(url, a['href']) for a in soup.find_all('a', href=True)]

    # Filter for is_valid(link)
    val_links = [link for link in links if is_valid(link)]

    print(f"Extracted {len(val_links)} valid links from {url}") # Debugging
    return val_links

def extract_next_links(url, resp):
    # Implementation required.
    # url: the URL that was used to get the page
    # resp.url: the actual url of the page
    # resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
    # resp.error: when status is not 200, you can check the error here, if needed.
    # resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
    #         resp.raw_response.url: the url, again
    #         resp.raw_response.content: the content of the page!
    # Return a list with the hyperlinks (as strings) scrapped from resp.raw_response.content
    return list()

def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    try:
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            return False

        # Filter for only specificed domains
        good_domains = {"ics.uci.edu", "cs.uci.edu", "informatics.uci.edu", "stat.uci.edu"}
        if parsed.netloc not in good_domains:
            return False

        if re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz"
            + r"|bak|sql|mdb|db|sqlite|ini|log|cfg"
            + r"|vdi|vmdk|qcow2|img|mat|sav|dta|spss"
            + r"|xz|lzma|zst|tar\.xz|bat|cmd|scr|vbs|apk)$", parsed.path.lower()):
            print(f"Blocked {url} (Invalid file type matched)") # Debugging
            return False

        return True
        

    except Exception as e:
        print(f"Error checking {url}: {e}") # Debugging
        return False
