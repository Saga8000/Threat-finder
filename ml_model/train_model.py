import os
import numpy as np
import pandas as pd
import joblib
import random
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from datetime import datetime

def generate_synthetic_data(num_samples=1000):
    """Generate synthetic malware analysis data."""
    np.random.seed(42)
    random.seed(42)
    
    # Define threat actors
    threat_actors = ['APT29', 'Lazarus', 'APT1', 'FIN7', 'Benign']
    file_types = ['exe', 'dll', 'doc', 'pdf', 'js', 'vbs']
    target_sectors = ['financial', 'government', 'healthcare', 'education', 'energy', 'technology', 'unknown']
    asns = ['AS12345', 'AS23456', 'AS34567', 'AS45678', 'AS56789']
    
    data = []
    
    for _ in range(num_samples):
        # Generate random features
        is_malicious = random.random() > 0.3  # 70% malicious, 30% benign
        
        if is_malicious:
            threat_actor = random.choice(threat_actors[:-1])  # Exclude 'Benign'
            is_packed = random.random() > 0.7  # 30% chance of being packed
            is_signed = random.random() > 0.8  # 20% chance of being signed
            has_anti_debug = random.random() > 0.6  # 40% chance
            has_vm_evasion = random.random() > 0.7  # 30% chance
            suspicious_api_count = int(np.random.poisson(5) + 1)  # 1-15 range
            has_ip = int(random.random() > 0.4)  # 60% chance
            has_domain = int(random.random() > 0.3)  # 70% chance
            entropy = np.random.normal(6.5, 1.5)  # Around 6.5 with some variance
            entropy = max(0, min(entropy, 8))  # Clamp between 0-8
        else:
            threat_actor = 'Benign'
            is_packed = random.random() > 0.9  # 10% chance of being packed
            is_signed = random.random() > 0.5  # 50% chance of being signed
            has_anti_debug = random.random() > 0.9  # 10% chance
            has_vm_evasion = random.random() > 0.9  # 10% chance
            suspicious_api_count = int(np.random.poisson(1))  # 0-5 range
            has_ip = int(random.random() > 0.8)  # 20% chance
            has_domain = int(random.random() > 0.7)  # 30% chance
            entropy = np.random.normal(4.5, 1.0)  # Lower entropy for benign
            entropy = max(0, min(entropy, 7))  # Clamp between 0-7
        
        file_type = random.choice(file_types)
        asn = random.choice(asns)
        target_sector = random.choice(target_sectors)
        
        data.append([
            threat_actor,
            suspicious_api_count,
            has_ip,
            has_domain,
            is_packed,
            is_signed,
            has_anti_debug,
            has_vm_evasion,
            entropy,
            file_type,
            asn,
            target_sector
        ])
    
    # Create DataFrame
    columns = [
        'threat_actor',
        'suspicious_api_count',
        'has_ip',
        'has_domain',
        'is_packed',
        'is_signed',
        'has_anti_debug',
        'has_vm_evasion',
        'entropy',
        'file_type',
        'asn',
        'target_sector'
    ]
    
    return pd.DataFrame(data, columns=columns)

def train_model():
    """
    Train and save the malware detection model.
    
    This function:
    1. Generates synthetic training data
    2. Preprocesses the data
    3. Trains a RandomForest classifier
    4. Saves the model and encoders
    5. Prints evaluation metrics
    """
    print("Starting model training...")
    
    # Generate synthetic data
    print("Generating synthetic data...")
    df = generate_synthetic_data(num_samples=5000)  # Generate 5000 samples
    
    # Save the dataset for reference
    os.makedirs('data', exist_ok=True)
    df.to_csv('data/synthetic_malware_dataset.csv', index=False)
    print(f"Generated dataset with {len(df)} samples")
    
    # Separate features and target
    X = df.drop('threat_actor', axis=1)
    y = df['threat_actor']
    
    # Encode categorical variables
    print("Encoding categorical features...")
    label_encoders = {}
    categorical_cols = ['file_type', 'asn', 'target_sector']
    
    for col in categorical_cols:
        le = LabelEncoder()
        X[col] = le.fit_transform(X[col].astype(str))
        label_encoders[col] = le
    
    # Split the data
    print("Splitting data into train/test sets...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Train the model
    print("Training RandomForest model...")
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1,
        verbose=1
    )
    
    model.fit(X_train, y_train)
    
    # Evaluate the model
    print("\nModel Evaluation:")
    print("-" * 50)
    
    # Training accuracy
    train_accuracy = model.score(X_train, y_train)
    print(f"Training Accuracy: {train_accuracy:.4f}")
    
    # Test accuracy
    test_accuracy = model.score(X_test, y_test)
    print(f"Test Accuracy: {test_accuracy:.4f}")
    
    # Detailed classification report
    y_pred = model.predict(X_test)
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, digits=4))
    
    # Feature importance
    feature_importance = pd.DataFrame({
        'feature': X.columns,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    print("\nFeature Importance:")
    print(feature_importance)
    
    # Save the model and encoders
    print("\nSaving model and encoders...")
    os.makedirs('ml_model', exist_ok=True)
    
    # Save model
    model_path = os.path.join('ml_model', 'model.pkl')
    joblib.dump(model, model_path)
    
    # Save label encoders
    encoders_path = os.path.join('ml_model', 'label_encoders.pkl')
    joblib.dump(label_encoders, encoders_path)
    
    # Save feature names for reference
    feature_names_path = os.path.join('ml_model', 'feature_names.pkl')
    joblib.dump(list(X.columns), feature_names_path)
    
    print(f"\nModel saved to: {os.path.abspath(model_path)}")
    print(f"Label encoders saved to: {os.path.abspath(encoders_path)}")
    print("\nTraining completed successfully!")

if __name__ == "__main__":
    train_model()