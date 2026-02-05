"""
Model Training for Intrusion Detection System
Implements and compares multiple ML models
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_auc_score
)
import matplotlib.pyplot as plt
import matplotlib
import seaborn as sns
import joblib
import time
from data_loader import IDSDataLoader

matplotlib.use('Agg')  # Use non-interactive backend


class IDSModelTrainer:
    """Train and evaluate intrusion detection models"""

    def __init__(self):
        self.models = {}
        self.results = {}
        self.best_model = None
        self.best_model_name = None

    def initialize_models(self):
        """Initialize different ML models"""
        self.models = {
            'Random Forest': RandomForestClassifier(
                n_estimators=100,
                max_depth=20,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                n_jobs=-1
            ),
            'Decision Tree': DecisionTreeClassifier(
                max_depth=15,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42
            ),
            'Gradient Boosting': GradientBoostingClassifier(
                n_estimators=100,
                learning_rate=0.1,
                max_depth=7,
                random_state=42
            ),
            'Logistic Regression': LogisticRegression(
                max_iter=1000,
                random_state=42,
                n_jobs=-1
            )
        }

        print(f"Initialized {len(self.models)} models")
        return self.models

    def train_model(self, model_name, model, X_train, y_train, X_val, y_val):
        """Train a single model and evaluate on validation set"""
        print(f"\n{'='*60}")
        print(f"Training {model_name}...")
        print(f"{'='*60}")

        start_time = time.time()

        # Train the model
        model.fit(X_train, y_train)

        training_time = time.time() - start_time

        # Make predictions
        y_train_pred = model.predict(X_train)
        y_val_pred = model.predict(X_val)

        # Calculate metrics
        train_metrics = self.calculate_metrics(y_train, y_train_pred)
        val_metrics = self.calculate_metrics(y_val, y_val_pred)

        # Store results
        self.results[model_name] = {
            'model': model,
            'train_metrics': train_metrics,
            'val_metrics': val_metrics,
            'training_time': training_time,
            'y_val_pred': y_val_pred
        }

        # Print results
        print(f"\nTraining Time: {training_time:.2f} seconds")
        print("\nTraining Set Performance:")
        self.print_metrics(train_metrics)
        print("\nValidation Set Performance:")
        self.print_metrics(val_metrics)

        return model

    def calculate_metrics(self, y_true, y_pred):
        """Calculate performance metrics"""
        metrics = {
            'accuracy': accuracy_score(y_true, y_pred),
            'precision': precision_score(y_true, y_pred, zero_division=0),
            'recall': recall_score(y_true, y_pred, zero_division=0),
            'f1': f1_score(y_true, y_pred, zero_division=0),
            'confusion_matrix': confusion_matrix(y_true, y_pred)
        }

        try:
            metrics['roc_auc'] = roc_auc_score(y_true, y_pred)
        except ValueError:
            metrics['roc_auc'] = None

        return metrics

    def print_metrics(self, metrics):
        """Print performance metrics in a formatted way"""
        print(f"  Accuracy:  {metrics['accuracy']:.4f}")
        print(f"  Precision: {metrics['precision']:.4f}")
        print(f"  Recall:    {metrics['recall']:.4f}")
        print(f"  F1-Score:  {metrics['f1']:.4f}")
        if metrics['roc_auc'] is not None:
            print(f"  ROC-AUC:   {metrics['roc_auc']:.4f}")
        print("\n  Confusion Matrix:")
        print(f"  {metrics['confusion_matrix']}")

    def train_all_models(self, X_train, y_train, X_val, y_val):
        """Train all initialized models"""
        self.initialize_models()

        for model_name, model in self.models.items():
            self.train_model(model_name, model, X_train, y_train, X_val, y_val)

        # Find best model based on F1 score on validation set
        best_f1 = 0
        for model_name, results in self.results.items():
            f1 = results['val_metrics']['f1']
            if f1 > best_f1:
                best_f1 = f1
                self.best_model_name = model_name
                self.best_model = results['model']

        print(f"\n{'='*60}")
        print(f"Best Model: {self.best_model_name} (F1: {best_f1:.4f})")
        print(f"{'='*60}")

        return self.best_model

    def evaluate_on_test(self, X_test, y_test):
        """Evaluate best model on test set"""
        if self.best_model is None:
            print("No model has been trained yet!")
            return

        print(f"\n{'='*60}")
        print(f"Evaluating {self.best_model_name} on Test Set")
        print(f"{'='*60}")

        y_test_pred = self.best_model.predict(X_test)
        test_metrics = self.calculate_metrics(y_test, y_test_pred)

        print("\nTest Set Performance:")
        self.print_metrics(test_metrics)

        return test_metrics, y_test_pred

    def plot_confusion_matrix(self, y_true, y_pred, title='Confusion Matrix'):
        """Plot confusion matrix"""
        cm = confusion_matrix(y_true, y_pred)

        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                    xticklabels=['Normal', 'Attack'],
                    yticklabels=['Normal', 'Attack'])
        plt.title(title)
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
        plt.tight_layout()

        return plt.gcf()

    def plot_model_comparison(self):
        """Plot comparison of all models"""
        if not self.results:
            print("No models have been trained yet!")
            return

        metrics_df = []
        for model_name, results in self.results.items():
            val_metrics = results['val_metrics']
            metrics_df.append({
                'Model': model_name,
                'Accuracy': val_metrics['accuracy'],
                'Precision': val_metrics['precision'],
                'Recall': val_metrics['recall'],
                'F1-Score': val_metrics['f1']
            })

        metrics_df = pd.DataFrame(metrics_df)

        fig, ax = plt.subplots(figsize=(12, 6))
        metrics_df.set_index('Model')[['Accuracy', 'Precision', 'Recall', 'F1-Score']].plot(
            kind='bar', ax=ax, width=0.8
        )
        plt.title('Model Performance Comparison (Validation Set)', fontsize=14, fontweight='bold')
        plt.ylabel('Score', fontsize=12)
        plt.xlabel('Model', fontsize=12)
        plt.ylim(0, 1.0)
        plt.legend(loc='lower right')
        plt.xticks(rotation=45, ha='right')
        plt.grid(axis='y', alpha=0.3)
        plt.tight_layout()

        return fig

    def get_feature_importance(self, feature_names, top_n=20):
        """Get feature importance from the best model"""
        if self.best_model is None:
            print("No model has been trained yet!")
            return None

        if not hasattr(self.best_model, 'feature_importances_'):
            print(f"{self.best_model_name} does not support feature importance")
            return None

        importances = self.best_model.feature_importances_
        indices = np.argsort(importances)[::-1][:top_n]

        fig, ax = plt.subplots(figsize=(10, 8))
        plt.barh(range(top_n), importances[indices])
        plt.yticks(range(top_n), [feature_names[i] for i in indices])
        plt.xlabel('Importance')
        plt.title(f'Top {top_n} Feature Importance - {self.best_model_name}')
        plt.gca().invert_yaxis()
        plt.tight_layout()

        return fig

    def save_best_model(self, filepath='../models/best_ids_model.pkl'):
        """Save the best model"""
        if self.best_model is None:
            print("No model has been trained yet!")
            return

        # Create directory if it doesn't exist
        import os
        os.makedirs(os.path.dirname(filepath), exist_ok=True)

        joblib.dump(self.best_model, filepath)

        joblib.dump(self.best_model, filepath)
        print(f"\nBest model ({self.best_model_name}) saved to {filepath}")

    def load_model(self, filepath='../models/best_ids_model.pkl'):
        """Load a saved model"""
        self.best_model = joblib.load(filepath)
        print(f"Model loaded from {filepath}")
        return self.best_model


def main():
    """Main training pipeline"""
    print("=" * 60)
    print("INTRUSION DETECTION SYSTEM - MODEL TRAINING")
    print("=" * 60)

    # Load and preprocess data
    print("\n1. Loading and preprocessing data...")
    loader = IDSDataLoader()
    df = loader.create_sample_data(n_samples=10000)
    X, y_binary, y_multi = loader.preprocess_data(df)

    # Split data
    print("\n2. Splitting data into train/val/test sets...")
    X_train, X_val, X_test, y_train, y_val, y_test = loader.split_data(X, y_binary)

    print(f"   Train: {X_train.shape[0]} samples")
    print(f"   Val:   {X_val.shape[0]} samples")
    print(f"   Test:  {X_test.shape[0]} samples")

    # Handle class imbalance with random oversampling
    print("\n3. Handling class imbalance with random oversampling...")

    # Convert to numpy if needed
    if hasattr(y_train, 'values'):
        y_train_np = y_train.values
    else:
        y_train_np = np.array(y_train)

    # Find minority and majority classes
    unique, counts = np.unique(y_train_np, return_counts=True)
    minority_class = unique[np.argmin(counts)]
    minority_count = counts.min()
    majority_count = counts.max()

    # Oversample minority class
    minority_indices = np.where(y_train_np == minority_class)[0]

    # Randomly sample minority class with replacement
    n_samples_needed = majority_count - minority_count
    oversampled_indices = np.random.choice(minority_indices, n_samples_needed, replace=True)

    # Combine original and oversampled data
    all_indices = np.concatenate([np.arange(len(y_train_np)), oversampled_indices])
    X_train_balanced = X_train[all_indices]
    y_train_balanced = y_train_np[all_indices]

    print(f"   Original training samples: {len(y_train_np)}")
    print(f"   After oversampling: {len(y_train_balanced)}")
    print(f"   Class distribution: {np.bincount(y_train_balanced)}")

    # Train models
    print("\n4. Training models...")
    trainer = IDSModelTrainer()
    trainer.train_all_models(X_train_balanced, y_train_balanced, X_val, y_val)

    # Evaluate on test set
    print("\n5. Final evaluation on test set...")
    test_metrics, y_test_pred = trainer.evaluate_on_test(X_test, y_test)

    # Save results
    print("\n6. Saving results...")
    loader.save_preprocessors('../models')
    trainer.save_best_model('../models/best_ids_model.pkl')

    # Generate visualizations
    print("\n7. Generating visualizations...")

    # Create visualizations directory if it doesn't exist
    import os
    os.makedirs('../visualizations', exist_ok=True)

    # Confusion matrix
    cm_fig = trainer.plot_confusion_matrix(y_test, y_test_pred,
                                           title=f'{trainer.best_model_name} - Test Set Confusion Matrix')
    cm_fig.savefig('../visualizations/confusion_matrix.png', dpi=300, bbox_inches='tight')
    print("   Saved: confusion_matrix.png")

    # Model comparison
    comp_fig = trainer.plot_model_comparison()
    comp_fig.savefig('../visualizations/model_comparison.png', dpi=300, bbox_inches='tight')
    print("   Saved: model_comparison.png")

    # Feature importance
    fi_fig = trainer.get_feature_importance(loader.feature_names, top_n=20)
    if fi_fig is not None:
        fi_fig.savefig('../visualizations/feature_importance.png', dpi=300, bbox_inches='tight')
        print("   Saved: feature_importance.png")

    print("\n" + "=" * 60)
    print("TRAINING COMPLETE!")
    print("=" * 60)
    print(f"\nBest Model: {trainer.best_model_name}")
    print(f"Test Accuracy: {test_metrics['accuracy']:.4f}")
    print(f"Test F1-Score: {test_metrics['f1']:.4f}")
    print("\nModel and preprocessors saved in ../models/")
    print("Visualizations saved in ../visualizations/")


if __name__ == "__main__":
    main()
