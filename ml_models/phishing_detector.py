import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import BaggingClassifier, StackingClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report, confusion_matrix
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import Dense, Dropout
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping
from imblearn.over_sampling import SMOTE
import joblib
import json
from datetime import datetime
import os

class HybridPhishingDetector:
    def __init__(self):
        self.scaler = StandardScaler()
        self.ann_model = None
        self.stacked_model = None
        self.feature_names = None
        self.training_history = {}
        
    def load_data(self, file_path):
        """Load and preprocess dataset"""
        df = pd.read_csv(file_path)
        
        # Separate features and target
        if 'url' in df.columns:
            df = df.drop('url', axis=1)
        
        X = df.drop('label', axis=1)
        y = df['label']
        
        self.feature_names = X.columns.tolist()
        
        return X, y
    
    def preprocess_data(self, X, y, apply_smote=True):
        """Preprocess features and apply SMOTE"""
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Apply SMOTE for balanced training
        if apply_smote:
            smote = SMOTE(random_state=42)
            X_train_scaled, y_train = smote.fit_resample(X_train_scaled, y_train)
        
        return X_train_scaled, X_test_scaled, y_train, y_test
    
    def build_ann(self, input_dim):
        """Build Artificial Neural Network"""
        model = Sequential([
            Dense(128, activation='relu', input_dim=input_dim),
            Dropout(0.3),
            Dense(64, activation='relu'),
            Dropout(0.3),
            Dense(32, activation='relu'),
            Dropout(0.2),
            Dense(16, activation='relu'),
            Dense(1, activation='sigmoid')
        ])
        
        model.compile(optimizer=Adam(learning_rate=0.001),
                     loss='binary_crossentropy',
                     metrics=['accuracy'])
        
        return model
    
    def train_ann(self, X_train, y_train, X_test, y_test):
        """Train ANN model"""
        self.ann_model = self.build_ann(X_train.shape[1])
        
        early_stopping = EarlyStopping(monitor='val_loss', patience=10, restore_best_weights=True)
        
        history = self.ann_model.fit(
            X_train, y_train,
            validation_data=(X_test, y_test),
            epochs=100,
            batch_size=32,
            callbacks=[early_stopping],
            verbose=1
        )
        
        return history
    
    def build_stacked_ensemble(self, X_train, y_train):
        """Build Hybrid Stacked Ensemble: ANN + Bagging KNN + Logistic Regression"""
        
        # Base learners
        # 1. Bagging KNN
        knn = KNeighborsClassifier(n_neighbors=5)
        bagging_knn = BaggingClassifier(
            estimator=knn,
            n_estimators=10,
            random_state=42
        )
        
        # 2. Logistic Regression
        log_reg = LogisticRegression(max_iter=1000, random_state=42)
        
        # 3. ANN predictions as features (we'll use predict_proba)
        # For stacking, we need sklearn-compatible estimators
        # So we create a wrapper for ANN
        
        # Create stacking ensemble
        estimators = [
            ('bagging_knn', bagging_knn),
            ('logistic_regression', log_reg)
        ]
        
        # Meta-learner: Logistic Regression
        self.stacked_model = StackingClassifier(
            estimators=estimators,
            final_estimator=LogisticRegression(max_iter=1000),
            cv=5
        )
        
        # Train stacked model
        self.stacked_model.fit(X_train, y_train)
        
        return self.stacked_model
    
    def train_full_model(self, file_path, apply_smote=True, k_folds=5):
        """Complete training pipeline"""
        print("Loading data...")
        X, y = self.load_data(file_path)
        
        print(f"Dataset shape: {X.shape}")
        print(f"Features: {len(self.feature_names)}")
        
        print("\nPreprocessing data...")
        X_train, X_test, y_train, y_test = self.preprocess_data(X, y, apply_smote)
        
        print(f"Training samples: {X_train.shape[0]}")
        print(f"Test samples: {X_test.shape[0]}")
        
        # Train ANN
        print("\n=== Training ANN ===")
        ann_history = self.train_ann(X_train, y_train, X_test, y_test)
        
        # Evaluate ANN
        ann_pred = (self.ann_model.predict(X_test) > 0.5).astype(int)
        ann_metrics = {
            'accuracy': accuracy_score(y_test, ann_pred),
            'precision': precision_score(y_test, ann_pred),
            'recall': recall_score(y_test, ann_pred),
            'f1_score': f1_score(y_test, ann_pred)
        }
        
        print(f"\nANN Performance:")
        print(f"Accuracy: {ann_metrics['accuracy']:.4f}")
        print(f"Precision: {ann_metrics['precision']:.4f}")
        print(f"Recall: {ann_metrics['recall']:.4f}")
        print(f"F1-Score: {ann_metrics['f1_score']:.4f}")
        
        # Train Stacked Ensemble
        print("\n=== Training Stacked Ensemble ===")
        self.build_stacked_ensemble(X_train, y_train)
        
        # Evaluate Stacked Model
        stacked_pred = self.stacked_model.predict(X_test)
        stacked_metrics = {
            'accuracy': accuracy_score(y_test, stacked_pred),
            'precision': precision_score(y_test, stacked_pred),
            'recall': recall_score(y_test, stacked_pred),
            'f1_score': f1_score(y_test, stacked_pred)
        }
        
        print(f"\nStacked Ensemble Performance:")
        print(f"Accuracy: {stacked_metrics['accuracy']:.4f}")
        print(f"Precision: {stacked_metrics['precision']:.4f}")
        print(f"Recall: {stacked_metrics['recall']:.4f}")
        print(f"F1-Score: {stacked_metrics['f1_score']:.4f}")
        
        # K-Fold Cross Validation
        print(f"\n=== {k_folds}-Fold Cross Validation ===")
        skf = StratifiedKFold(n_splits=k_folds, shuffle=True, random_state=42)
        cv_scores = cross_val_score(self.stacked_model, X_train, y_train, cv=skf, scoring='accuracy')
        
        print(f"CV Scores: {cv_scores}")
        print(f"Mean CV Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
        
        # Store training history
        self.training_history = {
            'ann_metrics': ann_metrics,
            'stacked_metrics': stacked_metrics,
            'cv_scores': cv_scores.tolist(),
            'cv_mean': float(cv_scores.mean()),
            'cv_std': float(cv_scores.std()),
            'training_date': datetime.now().isoformat(),
            'dataset_path': file_path,
            'features_count': len(self.feature_names),
            'training_samples': int(X_train.shape[0]),
            'test_samples': int(X_test.shape[0])
        }
        
        return self.training_history
    
    def save_models(self, output_dir='ml_models/trained'):
        """Save trained models"""
        os.makedirs(output_dir, exist_ok=True)
        
        # Save ANN
        self.ann_model.save(os.path.join(output_dir, 'ann_model.h5'))
        
        # Save Stacked Ensemble
        joblib.dump(self.stacked_model, os.path.join(output_dir, 'stacked_ensemble.pkl'))
        
        # Save Scaler
        joblib.dump(self.scaler, os.path.join(output_dir, 'scaler.pkl'))
        
        # Save feature names and history
        metadata = {
            'feature_names': self.feature_names,
            'training_history': self.training_history
        }
        
        with open(os.path.join(output_dir, 'metadata.json'), 'w') as f:
            json.dump(metadata, f, indent=4)
        
        print(f"\nModels saved to {output_dir}")
    
    def load_models(self, model_dir='ml_models/trained'):
        """Load trained models"""
        self.ann_model = load_model(os.path.join(model_dir, 'ann_model.h5'))
        self.stacked_model = joblib.load(os.path.join(model_dir, 'stacked_ensemble.pkl'))
        self.scaler = joblib.load(os.path.join(model_dir, 'scaler.pkl'))
        
        with open(os.path.join(model_dir, 'metadata.json'), 'r') as f:
            metadata = json.load(f)
            self.feature_names = metadata['feature_names']
            self.training_history = metadata['training_history']
        
        print(f"Models loaded from {model_dir}")
    
    def predict(self, url_features):
        """Predict if URL is phishing or legitimate"""
        try:
            # Ensure features are in correct order based on feature_names
            features_list = [url_features.get(name, 0) for name in self.feature_names]
            features_df = pd.DataFrame([features_list], columns=self.feature_names)
            
            # Scale features
            features_scaled = self.scaler.transform(features_df)
            
            # Get predictions from both models
            ann_pred_proba = float(self.ann_model.predict(features_scaled, verbose=0)[0][0])
            stacked_pred_proba = float(self.stacked_model.predict_proba(features_scaled)[0][1])
            
            # Average predictions (ensemble)
            final_proba = (ann_pred_proba + stacked_pred_proba) / 2
            final_pred = 1 if final_proba > 0.5 else 0
            
            # Determine confidence (probability of the predicted class)
            if final_pred == 1:  # Phishing predicted
                confidence = final_proba  # How confident it's phishing
            else:  # Legitimate predicted
                confidence = 1 - final_proba  # How confident it's legitimate
            
            result = {
                'prediction': 'phishing' if final_pred == 1 else 'legitimate',
                'confidence': confidence,  # This is 0-1 scale
                'ann_confidence': ann_pred_proba,
                'stacked_confidence': stacked_pred_proba,
                'final_probability': final_proba  # Raw probability of phishing
            }
            
            return result
        except Exception as e:
            print(f"Error in predict: {e}")
            import traceback
            traceback.print_exc()
            # Return safe default
            return {
                'prediction': 'legitimate',
                'confidence': 0.5,
                'ann_confidence': 0.5,
                'stacked_confidence': 0.5,
                'final_probability': 0.5
            }

# Training script
if __name__ == '__main__':
    detector = HybridPhishingDetector()
    
    # Train model
    history = detector.train_full_model(
        file_path='../datasets/phishing_dataset.csv',
        apply_smote=True,
        k_folds=5
    )
    
    # Save models
    detector.save_models()
    
    print("\n=== Training Complete ===")
