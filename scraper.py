import re
from collections import Counter, defaultdict
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import os
from simhash import Simhash
from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS

ERR_FILE = "error_log.txt"
UNIQUE_FILE = "unique_urls.txt"             # Stores unique urls
LONGEST_FILE = "longest_page.txt"           # Stores longest page
longest_page = {"url": "", "word_count": 0} # Dict to keep track of longest_page
COMMON_WORDS = "common_words.txt"
SUBDOMAINS = "subdomains.txt"
simhashes = set() # Store Simhashes

word_counter = Counter()
subdomain_counter = defaultdict(int)
STOPWORDS = set(ENGLISH_STOP_WORDS)

def update_longest(url, text):
    # Updates longest_page based on word count then saves to disk
    global longest_page
    word_count = len(re.findall(r"\w+", text))
    if word_count > longest_page["word_count"]:
        longest_page = {"url": url, "word_count": word_count}
        with open(LONGEST_FILE, "w") as f:
            f.write(f"Longest Page URL: {url}\nWordCount: {word_count}\n")
        print(f"Updated longest page: {url} ({word_count} words)")

def compute_simhash(text):
    # Computes the Simhash of the given text
    return Simhash(text).value

def load_unique_urls():
    # Loads unique URLs from disk into a set
    if os.path.exists(UNIQUE_FILE):
        with open(UNIQUE_FILE, "r") as f:
            return set(line.strip() for line in f)
    return set()

def save_unique_url(url):
    # URLs to be saved must be unique 
    url = remove_fragment(url)
    if url not in unique_urls:
        unique_urls.add(url)
        with open(UNIQUE_FILE, "a") as f:
            f.write(url + "\n")

unique_urls = load_unique_urls() # Cache for recent URLs loaded in from disk

def remove_fragment(url):
    # Removes fragment from url
    parsed = urlparse(url)
    return parsed._replace(fragment="").geturl()

def log_error(message):
    # Logs any encountered errors to error_log.text
    with open(ERR_FILE, "a") as f:
        f.write(message + "\n")

def save_common_words():
    with open(COMMON_WORDS, "w") as f:
        for word, freq in word_counter.most_common(50):
            f.write(f"{word}: {freq}\n")

def save_subdomains():
    with open(SUBDOMAINS, "w") as f:
        for subdomain, count in sorted(subdomain_counter.items()):
            f.write(f"{subdomain}, {count}\n")

def extract_text(soup):
    text = soup.get_text(" ")
    # Keep apostrophes, pass by short words
    words = re.findall(r"\b[a-zA-Z][a-zA-Z']{2,}\b", text.lower())
    filtered_words = [word for word in words if word not in STOPWORDS and not word.isdigit()]
    # Update global counter for Q3
    word_counter.update(filtered_words)
    save_common_words()

def count_subdomain(url):
    # Increment global counter for Q4
    parsed = urlparse(url)
    if "ics.uci.edu" in parsed.netloc:
        subdomain_counter[parsed.netloc] += 1
        save_subdomains()

def is_low_info(soup):
    # Returns True if page is a low info page
    text = soup.get_text(separator=' ')
    total_words = text.split()

    # Installed heuristics to determine if low-info or not
    if len(total_words) < 50: # Too short
        return True

    links = len(soup.find_all('a'))
    if links > 100 and len(total_words) / links < 2: # Evaluate word to link ratio
        return True
    
    return False

def scraper(url, resp):
    #links = extract_next_links(url, resp)
    #return [link for link in links if is_valid(link)]

    # Detects redirects and adds redirected link to frontier without processing
    if resp.status in {301, 302, 307, 308} and resp.raw_response:
        redir_url = resp.raw_response.url
        print(f"Redirect detected: {url} -> {redir_url}")
        url = remove_fragment(redir_url)
        return [url]
    
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

    # Detect if page is valid using SimHash
    current_simhash = compute_simhash(html_con)
    for known_simhash in simhashes:
        if hamming_distance(current_simhash, known_simhash) < 5:
            return []

    simhashes.add(current_simhash)

    # Gather necessary data from valid page

    save_unique_url(url)    # Process text for Q1
    update_longest(url, html_con) # Process text for Q2
    extract_text(soup)      # Process text for Q3
    count_subdomain(url)    # Process subdomain for Q4
    
    # Extract all links from the page WHILE transforming all relative links into ABSOLUTE links
    links = extract_next_links(url, resp)

    print(f"Extracted {len(links)} valid links from {url}") # Debugging
    return links


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
    if resp.status != 200 or not resp.raw_response:
        return []
    
    html_con = resp.raw_response.content
    soup = BeautifulSoup(html_con, "html.parser")
    
    links = [urljoin(url, a['href']) for a in soup.find_all('a', href=True)]
    return [remove_fragment(link) for link in links if is_valid(link, html_con)]

def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    try:
        parsed = urlparse(url)
        parsed = parsed._replace(fragment="") # Remove fragment

        if parsed.scheme not in set(["http", "https"]):
            return False

        # Filter for only specificed domains and their subdomains
        good_domains = {"ics.uci.edu", "cs.uci.edu", "informatics.uci.edu", "stat.uci.edu"}
        if not any (parsed.netloc.endswith("." + domain) or parsed.netloc == domain for domain in good_domains):
            return False

        # Filter for any pages with this extension found
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
        return False

