import os
import sys

# Add project root to path
sys.path.append(os.getcwd())

from Mchine_Learning.Ai_model import VulnerabilityCheckerTraining

def main():
    print("[*] Starting AI Model Training with new features...")
    
    # Initialize trainer
    trainer = VulnerabilityCheckerTraining()
    
    # Define paths
    RECON_PATH = "Data/Datasets/web_recon_ml_dataset.csv"
    VULN_PATH = "Data/Datasets/vulnerability_ml_dataset.csv"
    
    # Train the model
    # This will use the FEATURE_COLS we just updated in Ai_model.py
    success = trainer.train_model(recon_path=RECON_PATH, vuln_path=VULN_PATH)
    
    if success:
        print("[+] Training completed successfully.")
        # Save the model
        model_path = "Data/vulnerability_model.pkl"
        trainer.save_model(model_path)
        print(f"[+] Model saved to {model_path}")
    else:
        print("[-] Training failed.")

if __name__ == "__main__":
    main()
