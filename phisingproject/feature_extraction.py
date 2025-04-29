import re
import socket
import whois
import datetime
from urllib.parse import urlparse

def extract_features(url):
    parsed = urlparse(url)
    hostname = parsed.netloc

    def safe_domain_lookup():
        try:
            domain_info = whois.whois(hostname)
            creation = domain_info.creation_date
            expiration = domain_info.expiration_date
            if isinstance(creation, list): creation = creation[0]
            if isinstance(expiration, list): expiration = expiration[0]
            now = datetime.datetime.now()
            age = (now - creation).days if creation else -1
            length = (expiration - now).days if expiration else -1
            return age, length, 1
        except:
            return -1, -1, 0

    domain_age, domain_length, whois_found = safe_domain_lookup()

    def safe_dns_check():
        try:
            socket.gethostbyname(hostname)
            return 1
        except:
            return 0

    # Start feature dict
    features = {
        'length_url': len(url),
        'length_hostname': len(hostname),
        'ip': 1 if re.match(r'\d+\.\d+\.\d+\.\d+', hostname) else 0,
        'nb_dots': url.count('.'),
        'nb_hyphens': url.count('-'),
        'nb_at': url.count('@'),
        'nb_qm': url.count('?'),
        'nb_and': url.count('&'),
        'nb_or': url.count('|'),
        'nb_eq': url.count('='),
        'nb_underscore': url.count('_'),
        'nb_tilde': url.count('~'),
        'nb_percent': url.count('%'),
        'nb_slash': url.count('/'),
        'nb_star': url.count('*'),
        'nb_colon': url.count(':'),
        'nb_comma': url.count(','),
        'nb_semicolumn': url.count(';'),
        'nb_dollar': url.count('$'),
        'nb_space': url.count(' '),
        'nb_www': url.count('www'),
        'nb_com': url.count('.com'),
        'nb_dslash': url.count('//'),
        'http_in_path': 1 if 'http' in parsed.path else 0,
        'https_token': 1 if 'https' in url else 0,
        'ratio_digits_url': sum(c.isdigit() for c in url) / len(url),
        'ratio_digits_host': sum(c.isdigit() for c in hostname) / len(hostname),
        'punycode': 1 if 'xn--' in hostname else 0,
        'port': 1 if parsed.port else 0,
        'tld_in_path': 1 if '.com' in parsed.path else 0,
        'tld_in_subdomain': 0,  # Placeholder
        'abnormal_subdomain': 0,  # Placeholder
        'nb_subdomains': hostname.count('.') - 1,
        'prefix_suffix': 1 if '-' in hostname else 0,
        'random_domain': 0,  # Placeholder
        'shortening_service': 1 if any(s in url for s in ['bit.ly', 'tinyurl', 'goo.gl']) else 0,
        'path_extension': 0,  # Placeholder
        'nb_redirection': 0,
        'nb_external_redirection': 0,
        'length_words_raw': len(url.split('/')),
        'char_repeat': 0,
        'shortest_words_raw': min([len(word) for word in url.split('/') if word], default=0),
        'shortest_word_host': min([len(word) for word in hostname.split('.') if word], default=0),
        'shortest_word_path': 0,
        'longest_words_raw': max([len(word) for word in url.split('/') if word], default=0),
        'longest_word_host': max([len(word) for word in hostname.split('.') if word], default=0),
        'longest_word_path': 0,
        'avg_words_raw': sum(len(word) for word in url.split('/') if word) / len([w for w in url.split('/') if w]),
        'avg_word_host': sum(len(word) for word in hostname.split('.') if word) / len([w for w in hostname.split('.') if w]),
        'avg_word_path': 0,
        'phish_hints': 0,
        'domain_in_brand': 0,
        'brand_in_subdomain': 0,
        'brand_in_path': 0,
        'suspecious_tld': 0,
        'statistical_report': 0,
        'nb_hyperlinks': 0,
        'ratio_intHyperlinks': 0,
        'ratio_extHyperlinks': 0,
        'ratio_nullHyperlinks': 0,
        'nb_extCSS': 0,
        'ratio_intRedirection': 0,
        'ratio_extRedirection': 0,
        'ratio_intErrors': 0,
        'ratio_extErrors': 0,
        'login_form': 0,
        'external_favicon': 0,
        'links_in_tags': 0,
        'submit_email': 0,
        'ratio_intMedia': 0,
        'ratio_extMedia': 0,
        'sfh': 0,
        'iframe': 0,
        'popup_window': 0,
        'safe_anchor': 0,
        'onmouseover': 0,
        'right_clic': 0,
        'empty_title': 0,
        'domain_in_title': 0,
        'domain_with_copyright': 0,
        'whois_registered_domain': whois_found,
        'domain_registration_length': domain_length,
        'domain_age': domain_age,
        'web_traffic': 0,
        'dns_record': safe_dns_check(),
        'google_index': 0,
        'page_rank': 0
    }

    return features
