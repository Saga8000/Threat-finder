from flask import Flask, render_template, request, redirect, url_for, flash, send_file, session
from werkzeug.utils import secure_filename
import os
import joblib
import json
from datetime import datetime
from utils.analysis import analyze_file, extract_features, analyze_url, extract_url_features
from utils.report_generator import generate_pdf_report

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['REPORT_FOLDER'] = 'reports'
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024  # 1GB max upload

# Ensure upload and report directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['REPORT_FOLDER'], exist_ok=True)

# Load ML model and encoders
try:
    model = joblib.load('ml_model/model.pkl')
    label_encoders = joblib.load('ml_model/label_encoders.pkl')
    print("ML model and encoders loaded successfully")
except Exception as e:
    print(f"Error loading ML model: {e}")
    model = None
    label_encoders = None

# Load threat actor knowledge base
try:
    with open('data/threat_actors.json', 'r') as f:
        threat_actors_kb = json.load(f)
    print("Threat actors knowledge base loaded successfully")
except Exception as e:
    print(f"Error loading threat actors KB: {e}")
    threat_actors_kb = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    analysis_type = request.form.get('analysis_type', 'file')
    
    if analysis_type == 'file':
        # Handle file analysis
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(url_for('index'))
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(url_for('index'))
        
        if file:
            # Check file size (1GB limit)
            max_size = 1024 * 1024 * 1024  # 1GB
            if file.content_length and file.content_length > max_size:
                flash(f'File size ({file.content_length / (1024*1024):.1f}MB) exceeds the maximum limit of 1GB.', 'error')
                return redirect(url_for('index'))

            try:
                # Save uploaded file
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)

                # Analyze file
                analysis_result = analyze_file(filepath)
                analysis_result['analysis_type'] = 'file'

            except Exception as e:
                flash(f'Error analyzing file: {str(e)}', 'error')
                return redirect(url_for('index'))
    
    elif analysis_type == 'url':
        # Handle URL analysis
        url = request.form.get('url', '').strip()
        if not url:
            flash('No URL provided', 'error')
            return redirect(url_for('index'))
        
        try:
            # Analyze URL
            analysis_result = analyze_url(url)
            analysis_result['analysis_type'] = 'url'
            
        except Exception as e:
            flash(f'Error analyzing URL: {str(e)}', 'error')
            return redirect(url_for('index'))
    
    else:
        flash('Invalid analysis type', 'error')
        return redirect(url_for('index'))
    
    # Extract features for ML (if applicable)
    if analysis_type == 'file':
        features = extract_features(analysis_result)
    else:
        features = extract_url_features(analysis_result)
    
    # Get target sector from form (if provided)
    target_sector = request.form.get('target_sector', 'unknown')
    features['target_sector'] = target_sector
    
    # ML Prediction
    ml_prediction = None
    if model and label_encoders:
        try:
            # Prepare features for prediction
            X_pred = prepare_features_for_prediction(features, label_encoders)
            
            # Get prediction probabilities
            probabilities = model.predict_proba([X_pred])[0]
            predicted_class_idx = probabilities.argmax()
            predicted_class = model.classes_[predicted_class_idx]
            confidence = probabilities[predicted_class_idx]
            
            # Get threat actor info
            threat_actor_info = threat_actors_kb.get(predicted_class, {})
            
            ml_prediction = {
                'threat_actor': predicted_class,
                'confidence': float(confidence),
                'probabilities': {cls: float(prob) for cls, prob in zip(model.classes_, probabilities)},
                'threat_actor_info': threat_actor_info
            }
            
            # Rule-based validation
            rule_confidence = validate_prediction_with_rules(analysis_result, predicted_class, analysis_type)
            ml_prediction['rule_confidence'] = rule_confidence
            
            # Final attribution decision
            if confidence >= 0.7 and rule_confidence == 'High':
                ml_prediction['final_decision'] = 'Likely'
            elif confidence >= 0.5 or rule_confidence in ['High', 'Medium']:
                ml_prediction['final_decision'] = 'Probable'
            else:
                ml_prediction['final_decision'] = 'Low Confidence'
                
        except Exception as e:
            print(f"ML prediction error: {e}")
            import traceback
            traceback.print_exc()
            ml_prediction = {'error': str(e)}
    
    analysis_result['ml_prediction'] = ml_prediction

    # Store analysis results in session for report regeneration
    import copy
    session_result = copy.deepcopy(analysis_result)

    # Convert sets to lists for JSON serialization
    def convert_sets_to_lists(obj):
        if isinstance(obj, set):
            return list(obj)
        elif isinstance(obj, dict):
            return {k: convert_sets_to_lists(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [convert_sets_to_lists(item) for item in obj]
        else:
            return obj

    session_result = convert_sets_to_lists(analysis_result)

    session['last_analysis'] = {
        'result': session_result,
        'type': analysis_type,
        'timestamp': datetime.now().timestamp()
    }

    # Generate report
    report_filename = f"report_{int(datetime.now().timestamp())}.pdf"
    report_path = os.path.join(app.config['REPORT_FOLDER'], report_filename)

    try:
        generate_pdf_report(analysis_result, report_path)
        print("PDF generation successful")
    except Exception as e:
        print(f"PDF generation error: {e}")
        import traceback
        traceback.print_exc()
    
    try:
        return render_template(
            'results.html',
            analysis=analysis_result,
            report_filename=report_filename
        )
    except Exception as e:
        print(f"Template rendering error: {e}")
        import traceback
        traceback.print_exc()
        flash(f'Error rendering results: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/download/<filename>')
def download_report(filename):
    """Download PDF report. Regenerate if file doesn't exist."""
    report_path = os.path.join(app.config['REPORT_FOLDER'], filename)

    # Check if file exists
    if not os.path.exists(report_path):
        # Try to regenerate from session data
        if 'last_analysis' in session:
            try:
                analysis_data = session['last_analysis']
                analysis_result = analysis_data['result']

                # Regenerate the report
                generate_pdf_report(analysis_result, report_path)
                print(f"Report regenerated: {filename}")
            except Exception as e:
                print(f"Report regeneration error: {e}")
                flash('Error regenerating report. Please re-run the analysis.', 'error')
                return redirect(url_for('index'))
        else:
            flash('Report file not found. Please re-run the analysis.', 'error')
            return redirect(url_for('index'))

    try:
        return send_file(
            report_path,
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        print(f"Download error: {e}")
        flash('Error downloading report. Please try again.', 'error')
        return redirect(url_for('index'))

def validate_prediction_with_rules(analysis_result, predicted_actor, analysis_type='file'):
    """Validate ML prediction with forensic rules."""
    rule_score = 0
    
    if analysis_type == 'file':
        # File-based rules
        pe_info = analysis_result.get('pe_info', {})
        network_indicators = analysis_result.get('network_indicators', {})
        
        # Check if threat actor patterns match analysis results
        actor_info = threat_actors_kb.get(predicted_actor, {})
        known_apis = actor_info.get('known_api_patterns', [])
        
        # API pattern matching
        if pe_info.get('imports'):
            for imp in pe_info['imports']:
                if any(api.lower() in imp.lower() for api in known_apis):
                    rule_score += 2
        
        # Suspicious indicators
        if pe_info.get('is_packed'):
            rule_score += 1
        if pe_info.get('has_anti_debug'):
            rule_score += 1
        if pe_info.get('has_vm_evasion'):
            rule_score += 1
        if network_indicators.get('ip_addresses'):
            rule_score += 1
        if network_indicators.get('domains'):
            rule_score += 1
    
    elif analysis_type == 'url':
        # URL-based rules
        suspicious_indicators = analysis_result.get('suspicious_indicators', {})
        network_indicators = analysis_result.get('network_indicators', {})
        
        # URL-specific suspicious patterns
        if suspicious_indicators.get('has_ip_in_domain'):
            rule_score += 3
        if suspicious_indicators.get('has_suspicious_tld'):
            rule_score += 2
        if suspicious_indicators.get('has_at_symbol'):
            rule_score += 3
        if suspicious_indicators.get('has_suspicious_words'):
            rule_score += 2
        if suspicious_indicators.get('has_encoded_chars'):
            rule_score += 1
        if suspicious_indicators.get('has_double_slash'):
            rule_score += 2
        if network_indicators.get('ip_addresses'):
            rule_score += 1
    
    # Determine confidence level
    if rule_score >= 4:
        return 'High'
    elif rule_score >= 2:
        return 'Medium'
    else:
        return 'Low'

def prepare_features_for_prediction(features, label_encoders):
    """Prepare features for model prediction."""
    # Convert features to model input format
    X = {
        'suspicious_api_count': features.get('suspicious_api_count', 0),
        'has_ip': features.get('has_ip', 0),
        'has_domain': features.get('has_domain', 0),
        'is_packed': features.get('is_packed', 0),
        'is_signed': features.get('is_signed', 0),
        'has_anti_debug': features.get('has_anti_debug', 0),
        'has_vm_evasion': features.get('has_vm_evasion', 0),
        'entropy': features.get('entropy', 0),
        'file_type': features.get('file_type', 'unknown'),
        'asn': features.get('asn', 'unknown'),
        'target_sector': features.get('target_sector', 'unknown')
    }
    
    # Encode categorical features
    for feature in ['file_type', 'asn', 'target_sector']:
        if feature in label_encoders:
            try:
                X[feature] = label_encoders[feature].transform([X[feature]])[0]
            except ValueError:
                # Handle unknown categories by using the first class or a default
                print(f"Warning: Unknown category '{X[feature]}' for feature '{feature}', using default")
                X[feature] = 0  # Use first class as default
    
    # Convert to list in correct order
    feature_order = [
        'suspicious_api_count', 'has_ip', 'has_domain', 'is_packed',
        'is_signed', 'has_anti_debug', 'has_vm_evasion', 'entropy',
        'file_type', 'asn', 'target_sector'
    ]
    return [X[feature] for feature in feature_order]

def validate_prediction_with_rules(analysis_result, predicted_class, analysis_type):
    """Validate ML prediction with rule-based checks."""
    confidence_level = 'Low'
    
    if analysis_type == 'file':
        threat_score = analysis_result.get('threat_score', 0)
        pe_info = analysis_result.get('pe_info', {})
        
        # High confidence rules
        if threat_score >= 70:
            confidence_level = 'High'
        elif threat_score >= 40:
            confidence_level = 'Medium'
        
        # Additional checks for known threat actor patterns
        if predicted_class == 'APT28' and pe_info.get('has_anti_debug', False):
            confidence_level = 'High'
        elif predicted_class == 'Lazarus' and pe_info.get('is_packed', False):
            confidence_level = 'High'
            
    elif analysis_type == 'url':
        threat_score = analysis_result.get('threat_score', 0)
        suspicious_indicators = analysis_result.get('suspicious_indicators', {})
        
        # URL-specific validation
        if threat_score >= 60:
            confidence_level = 'High'
        elif threat_score >= 30:
            confidence_level = 'Medium'
        
        # Check for known malicious patterns
        if predicted_class == 'APT28' and suspicious_indicators.get('has_suspicious_words', False):
            confidence_level = 'High'
    
    return confidence_level

if __name__ == '__main__':
    app.run(debug=True)