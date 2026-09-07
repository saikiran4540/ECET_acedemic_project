#!/usr/bin/env python
"""
Train phishing detector with new real-world dataset
"""

import sys
import os

# Add paths
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ml_models.phishing_detector import HybridPhishingDetector

def main():
    print("\n" + "="*70)
    print("PHISHING DETECTOR - TRAINING WITH REAL DATASET")
    print("="*70)
    
    detector = HybridPhishingDetector()
    
    dataset_path = 'datasets/phishing_dataset.csv'
    
    if not os.path.exists(dataset_path):
        print(f"Error: Dataset not found at {dataset_path}")
        return False
    
    print(f"\nTraining with dataset: {dataset_path}")
    
    try:
        # Train the model
        history = detector.train_full_model(
            file_path=dataset_path,
            apply_smote=True,
            k_folds=5
        )
        
        # Save models
        print("\nSaving trained models...")
        detector.save_models('ml_models/trained')
        
        print("\n" + "="*70)
        print("TRAINING COMPLETE!")
        print("="*70)
        print("\nModel Performance Summary:")
        print(f"  ANN Accuracy:               {history['ann_metrics']['accuracy']:.4f}")
        print(f"  Stacked Ensemble Accuracy:  {history['stacked_metrics']['accuracy']:.4f}")
        print(f"  Cross-Validation Accuracy:  {history['cv_mean']:.4f} ± {history['cv_std']:.4f}")
        print(f"\nDataset:")
        print(f"  Training samples: {history['training_samples']}")
        print(f"  Test samples:     {history['test_samples']}")
        print(f"  Features:         {history['features_count']}")
        print("="*70 + "\n")
        
        return True
        
    except Exception as e:
        print(f"Error during training: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
