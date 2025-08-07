# app.py
from flask import Flask, render_template, request, jsonify
import requests
import cohere
from urllib.parse import urlparse
import whois
import datetime
import re
import ssl
import socket
import random
from bs4 import BeautifulSoup

app = Flask(__name__)

# Initialize Cohere client
# IMPORTANT: Replace 'YOUR_COHERE_API_KEY_HERE' with your actual API key
co = cohere.Client('V4FQNrkjYNAYFWUuC4ZsITKuFzdeksOl7EKif9xg')

def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def get_domain_info(domain):
    try:
        w = whois.whois(domain)
        
        # Get creation date
        if isinstance(w.creation_date, list):
            creation_date = w.creation_date[0]
        else:
            creation_date = w.creation_date
        
        # Format creation date nicely
        if creation_date:
            # Format with ordinal suffix (1st, 2nd, 3rd, etc.)
            day = creation_date.day
            if 4 <= day <= 20 or 24 <= day <= 30:
                suffix = "th"
            else:
                suffix = ["st", "nd", "rd"][day % 10 - 1]
            
            formatted_date = creation_date.strftime(f"%A {day}{suffix}, %B %Y %I:%M %p")
            age = (datetime.datetime.now() - creation_date).days
            return {
                'creation_date': formatted_date,
                'age_days': age
            }
        return {
            'creation_date': 'Unknown',
            'age_days': 0
        }
    except Exception as e:
        print(f"Error getting domain info: {str(e)}")
        return {
            'creation_date': 'Unknown',
            'age_days': 0
        }

def check_https(url):
    try:
        # Extract domain from URL
        domain = urlparse(url).netloc
        
        # Create a socket connection
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # Check if certificate is valid
                ssl.match_hostname(cert, domain)
                
                return "Valid HTTPS Found", "success"
    except ssl.SSLError:
        return "Invalid or Expired Certificate", "danger"
    except Exception as e:
        return f"HTTPS Error: {str(e)}", "warning"

def get_blacklist_status(domain):
    """Simulated blacklist check (in a real app, use API like Google Safe Browsing)"""
    # For demo purposes, we'll simulate results
    # In production, you'd use an API like:
    # https://developers.google.com/safe-browsing
    
    # Simulated results - 5% chance of being blacklisted
    if random.random() < 0.05:
        return "Detected by multiple engines", "danger"
    
    # 10% chance of being suspicious
    if random.random() < 0.1:
        return "Suspicious activity detected", "warning"
    
    return "Not detected by any blacklist engine", "success"

def get_proximity_score(domain):
    """Simulated proximity to suspicious websites (in a real app, use threat intelligence API)"""
    # For demo purposes, we'll generate a random score
    # In production, you'd use an API like:
    # https://www.phishtank.com/developer_info.php
    
    # Generate a random score between 0-100
    score = random.randint(0, 100)
    
    # Determine status
    if score > 70:
        status = "danger"
    elif score > 40:
        status = "warning"
    else:
        status = "success"
        
    return score, status

def analyze_with_cohere(text):
    try:
        response = co.generate(
            model='command',
            prompt=f"""Analyze the following website content and determine if it's likely to be a scam. 
            Consider factors like suspicious offers, poor grammar, urgency tactics, and other red flags.
            
            Content: {text}
            
            Analysis:""",
            max_tokens=300,
            temperature=0.7,
            k=0,
            stop_sequences=[],
            return_likelihoods='NONE'
        )
        return response.generations[0].text
    except Exception as e:
        return f"Error analyzing with Cohere: {str(e)}"

def calculate_trust_index(domain_age, content, cohere_analysis, https_status, blacklist_status, proximity_score):
    """Calculate a trust index from 0-100% based on multiple factors"""
    trust_score = 100
    reasons = []
    
    # Domain age penalty (max 20 points)
    if domain_age < 365:  # Less than 1 year
        penalty = min(20, (365 - domain_age) / 18.25)  # 365/20 = 18.25
        trust_score -= penalty
        reasons.append(f"New domain ({domain_age} days old): -{penalty:.1f}% trust")
    
    # Common scam words penalty (max 15 points)
    scam_words = ['win', 'free', 'urgent', 'limited', 'offer', 'prize', 'congratulations', 'lottery', 'selected']
    word_count = sum(content.lower().count(word) for word in scam_words)
    if word_count > 0:
        penalty = min(15, word_count * 2)
        trust_score -= penalty
        reasons.append(f"Suspicious keywords detected: -{penalty:.1f}% trust")
    
    # Cohere analysis penalty (max 30 points)
    negative_phrases = ['likely scam', 'suspicious', 'fraudulent', 'high risk', 'be cautious', 'phishing']
    positive_phrases = ['likely legitimate', 'appears safe', 'low risk', 'trustworthy']
    
    negative_score = sum(cohere_analysis.lower().count(phrase) for phrase in negative_phrases) * 5
    positive_score = sum(cohere_analysis.lower().count(phrase) for phrase in positive_phrases) * 5
    
    ai_penalty = min(30, max(0, negative_score - positive_score))
    if ai_penalty > 0:
        trust_score -= ai_penalty
        reasons.append(f"AI detected red flags: -{ai_penalty:.1f}% trust")
    
    # HTTPS bonus/penalty
    if "valid" in https_status.lower():
        trust_score += 5
        reasons.append(f"Valid HTTPS: +5% trust")
    else:
        trust_score -= 15
        reasons.append(f"Invalid HTTPS: -15% trust")
    
    # Blacklist penalty
    if "detected" in blacklist_status.lower() or "suspicious" in blacklist_status.lower():
        penalty = 30 if "multiple" in blacklist_status.lower() else 15
        trust_score -= penalty
        reasons.append(f"Blacklist status: -{penalty}% trust")
    
    # Proximity penalty
    proximity_penalty = proximity_score * 0.3
    trust_score -= proximity_penalty
    reasons.append(f"Proximity to suspicious sites: -{proximity_penalty:.1f}% trust")
    
    # Ensure score is between 0-100
    trust_score = max(0, min(100, trust_score))
    
    # Determine status based on score
    if trust_score > 70:
        status = "High Trust"
        status_class = "success"
    elif trust_score > 40:
        status = "Medium Trust"
        status_class = "warning"
    else:
        status = "Low Trust"
        status_class = "danger"
    
    return {
        'score': round(trust_score),
        'status': status,
        'status_class': status_class,
        'reasons': reasons
    }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check_url():
    url = request.form.get('url')
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    if not is_valid_url(url):
        return jsonify({'error': 'Invalid URL format'}), 400
    
    try:
        # Get website content
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        # Extract text content using BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')
        text_content = soup.get_text()
        text_content = ' '.join(text_content.split()[:2000])  # Limit to first 2000 words
        
        # Get domain info
        domain = urlparse(url).netloc
        domain_info = get_domain_info(domain)
        
        # Get HTTPS status
        https_status, https_class = check_https(url)
        
        # Get blacklist status
        blacklist_status, blacklist_class = get_blacklist_status(domain)
        
        # Get proximity score
        proximity_score, proximity_class = get_proximity_score(domain)
        
        # Analyze with Cohere
        analysis = analyze_with_cohere(text_content)
        
        # Calculate trust index
        trust_index = calculate_trust_index(
            domain_info['age_days'], 
            text_content, 
            analysis,
            https_status,
            blacklist_status,
            proximity_score
        )
        
        return jsonify({
            'url': url,
            'domain': domain,
            'domain_creation_date': domain_info['creation_date'],
            'domain_age_days': domain_info['age_days'],
            'https_status': https_status,
            'https_class': https_class,
            'blacklist_status': blacklist_status,
            'blacklist_class': blacklist_class,
            'proximity_score': proximity_score,
            'proximity_class': proximity_class,
            'content_sample': text_content[:500] + '...',
            'analysis': analysis,
            'trust_index': trust_index['score'],
            'trust_status': trust_index['status'],
            'trust_class': trust_index['status_class'],
            'trust_reasons': trust_index['reasons'],
            'status': 'success'
        })
        
    except requests.exceptions.RequestException as e:
        return jsonify({'error': f'Failed to fetch URL: {str(e)}'}), 400
    except Exception as e:
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(debug=True)