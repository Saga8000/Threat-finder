# Web-Based Malware Forensic Analysis and Machine Learning-Based Attack Source Attribution System

Deployed on Vercel with Python 3.11.8

## Project Overview

This is a comprehensive web-based application for malware forensic analysis and probabilistic threat actor attribution. The system performs static analysis on uploaded files and uses machine learning to predict the most likely threat actor responsible for the malware.

**Academic Project**: This is designed as a final-year college project demonstrating cybersecurity, digital forensics, and machine learning integration.

## System Architecture

```
Browser → Web UI (HTML/Tailwind) → Flask Backend → Analysis Engine → ML Model → PDF Report
```

## Key Features

### 1. Malware Upload Module
- Secure file upload (EXE, DLL, APK, DOCM files)
- Automatic hash calculation (MD5, SHA256)
- File type detection
- Metadata extraction

### 2. Static Analysis Engine
- PE file analysis (imports, sections, signatures)
- String extraction and IOC identification
- Suspicious API detection
- Packer and obfuscation detection

### 3. IOC Extraction Module
- IP address extraction
- Domain name extraction
- URL pattern matching

### 4. Machine Learning Attribution Engine
- RandomForest classifier trained on synthetic malware dataset
- Probabilistic threat actor prediction
- Feature engineering from forensic analysis
- Confidence scoring

### 5. Rule-Based Validation Layer
- Cross-validation of ML predictions with forensic rules
- Confidence level assessment (Likely/Probable/Low Confidence)

### 6. Threat Actor Knowledge Base
- JSON-based database of known threat actors
- Country attribution, tactics, and target sectors
- API pattern matching

### 7. PDF Report Generation
- Comprehensive forensic report
- Analysis results and ML predictions
- Ethical disclaimers

## Technology Stack

- **Frontend**: HTML, Tailwind CSS
- **Backend**: Python Flask
- **Analysis**: hashlib, pefile, python-magic, re, os
- **Machine Learning**: scikit-learn, RandomForestClassifier
- **Database**: JSON (threat actors), SQLite (optional)
- **Reporting**: ReportLab PDF generation

## Installation and Setup

### Prerequisites
- Python 3.8 or higher
- pip package manager
- Windows OS (for PE file analysis with pefile)

### Installation Steps

1. **Clone or download the project**:
   ```bash
   cd your-project-directory
   ```

2. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Train the ML model** (if not already trained):
   ```bash
   python ml_model/train_model.py
   ```

4. **Run the application**:
   ```bash
   python app.py
   ```

5. **Access the web interface**:
   Open your browser and navigate to: `http://localhost:5000`

## Project Structure

```
malware-forensic-analysis/
├── app.py                          # Main Flask application
├── requirements.txt                # Python dependencies
├── Readme.md                       # Project documentation
├── data/
│   ├── threat_actors.json         # Threat actor knowledge base
│   ├── synthetic_malware_dataset.csv  # Training dataset
│   └── sample_malware.csv         # Sample data
├── ml_model/
│   ├── train_model.py             # ML model training script
│   ├── model.pkl                  # Trained RandomForest model
│   ├── label_encoders.pkl         # Feature encoders
│   └── feature_names.pkl          # Feature names
├── utils/
│   ├── analysis.py                # Static analysis functions
│   └── report_generator.py        # PDF report generation
├── templates/
│   ├── base.html                  # Base HTML template
│   ├── index.html                 # Upload page
│   └── results.html               # Analysis results page
├── static/
│   ├── css/
│   │   └── styles.css             # Custom styles
│   └── js/
│       └── main.js                # Frontend JavaScript
├── uploads/                       # Uploaded files directory
└── reports/                       # Generated PDF reports
```

## Machine Learning Model

### Dataset
- **Type**: Synthetic dataset (300-500 samples)
- **Features**: suspicious_api_count, has_ip, has_domain, is_packed, is_signed, has_anti_debug, has_vm_evasion, entropy, file_type, asn, target_sector
- **Target**: threat_actor (APT29, Lazarus, APT1, FIN7, Benign)

### Model Training
```bash
python ml_model/train_model.py
```

### Model Performance
- Algorithm: RandomForestClassifier
- Training Accuracy: ~98.5%
- Test Accuracy: ~47% (expected for synthetic data)
- Key Features: suspicious_api_count, entropy, target_sector

## Usage Instructions

1. **Start the application**:
   ```bash
   python app.py
   ```

2. **Upload a file**:
   - Click "Upload a file" on the homepage
   - Select a suspicious executable file
   - Optionally select target sector
   - Click "Analyze File"

3. **Review results**:
   - File information and hashes
   - Static analysis results
   - Extracted IOCs
   - ML-based threat actor prediction
   - Confidence scores

4. **Download report**:
   - Click "Download PDF Report" for comprehensive analysis

## Ethical and Legal Considerations

### Important Disclaimers
- **Educational Purpose Only**: This system is designed for academic and research purposes
- **No Real Malware Execution**: Uses static analysis only, no detonation or execution
- **Probabilistic Attribution**: Results are statistical predictions, not absolute identifications
- **Not a Substitute for Professional Analysis**: Always consult cybersecurity experts for real incidents

### Academic Compliance
- Suitable for college final-year projects
- Demonstrates integration of multiple technologies
- Includes proper ethical disclaimers
- Uses synthetic data to avoid real malware handling

## API Endpoints

- `GET /`: Homepage with file upload form
- `POST /analyze`: File analysis endpoint
- `GET /download/<filename>`: PDF report download

## Configuration

### Flask Configuration
- Upload limit: 16MB
- Secret key: Change in production
- Debug mode: Enabled for development

### ML Model Configuration
- Model: RandomForestClassifier
- Parameters: n_estimators=200, max_depth=15
- Features: 11 input features
- Classes: 5 threat actor categories

## Troubleshooting

### Common Issues
1. **Import Errors**: Ensure all dependencies are installed
2. **Model Loading**: Run `train_model.py` if model files are missing
3. **File Upload**: Check file size limits and allowed extensions
4. **PDF Generation**: Ensure ReportLab is properly installed

### Windows-Specific Notes
- Uses `python-magic-bin` for Windows compatibility
- PE analysis requires Windows PE files
- File paths use Windows conventions

## Future Enhancements

- Dynamic analysis integration (sandbox)
- YARA rule matching
- Threat intelligence API integration
- Advanced ML models (neural networks)
- Real-time analysis queue
- User authentication and audit logs

## Contributing

This is an academic project. For improvements:
1. Fork the repository
2. Create a feature branch
3. Make changes with proper documentation
4. Test thoroughly
5. Submit a pull request

## License

Educational use only. Not for commercial deployment without proper security auditing.

## Contact

For academic inquiries or project discussions, please refer to the project documentation or contact the development team.