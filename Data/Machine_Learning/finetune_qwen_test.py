import os
import pandas as pd
import torch
from datasets import Dataset
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    TrainingArguments,
    Trainer,
    DataCollatorForLanguageModeling
)
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training

# 1. Configuration
# Using the 1.5B version for a faster download and test. 
# Change to "Qwen/Qwen2.5-Coder-7B-Instruct" for the full model later.
MODEL_NAME = "Qwen/Qwen2.5-Coder-1.5B-Instruct"
OUTPUT_DIR = "./test_qwen_lora"

# Calculate paths relative to this script
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
VULN_CSV_PATH = os.path.join(BASE_DIR, "Data", "Datasets", "Datasets_for_Model_Evaluation", "vulnerability", "vulnerability_ml_dataset.csv")

def format_row_to_prompt(row):
    """
    Converts a tabular CSV row into a prompt for the NLP model.
    """
    # Extract vulnerabilities
    vulns = []
    if row.get('has_sql_injection') == 1: vulns.append("SQL Injection")
    if row.get('has_xss') == 1: vulns.append("Cross-Site Scripting (XSS)")
    if row.get('has_command_injection') == 1: vulns.append("Command Injection")
    if row.get('has_path_traversal') == 1: vulns.append("Path Traversal")
    
    vuln_text = ", ".join(vulns) if vulns else "Secure (No vulnerabilities detected)"
    
    # Create the prompt structure (Alpaca/Instruction format)
    instruction = "Analyze the following web endpoint and determine its vulnerabilities."
    input_text = f"URL: {row.get('url', 'Unknown')}\nPath Depth: {row.get('path_depth', 0)}\nQuery Params: {row.get('num_query_params', 0)}"
    output_text = f"Vulnerability Analysis: {vuln_text}"
    
    # Format for Qwen
    full_prompt = f"<|im_start|>user\n{instruction}\n{input_text}<|im_end|>\n<|im_start|>assistant\n{output_text}<|im_end|>"
    return full_prompt

def main():
    print(f"[*] Loading dataset from: {VULN_CSV_PATH}")
    if not os.path.exists(VULN_CSV_PATH):
        print("[-] Dataset not found! Please check the path.")
        return
        
    # 2. Load and Prepare Data (Just taking 50 rows for a quick test)
    df = pd.read_csv(VULN_CSV_PATH).head(50)
    df['text'] = df.apply(format_row_to_prompt, axis=1)
    
    dataset = Dataset.from_pandas(df[['text']])
    print(f"[+] Loaded {len(dataset)} rows for testing.")
    print("[+] Sample Prompt:")
    print(dataset[0]['text'])
    print("-" * 50)

    # 3. Load Tokenizer
    print(f"[*] Loading Tokenizer: {MODEL_NAME}")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME, trust_remote_code=True)
    tokenizer.pad_token = tokenizer.eos_token

    def tokenize_function(examples):
        return tokenizer(examples["text"], truncation=True, max_length=256)
        
    tokenized_dataset = dataset.map(tokenize_function, batched=True)

    # 4. Load Model
    print(f"[*] Loading Model: {MODEL_NAME}")
    # We load in bfloat16 or float16 to save memory. 
    # If you have bitsandbytes installed, you can add load_in_4bit=True
    model = AutoModelForCausalLM.from_pretrained(
        MODEL_NAME,
        torch_dtype=torch.float16,
        device_map="auto",
        trust_remote_code=True
    )

    # 5. Setup LoRA (PEFT)
    print("[*] Setting up LoRA Adapter...")
    lora_config = LoraConfig(
        r=8, 
        lora_alpha=16, 
        target_modules=["q_proj", "v_proj"], 
        lora_dropout=0.05,
        bias="none",
        task_type="CAUSAL_LM"
    )
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()

    # 6. Configure Trainer (Just 3 steps to test if it works)
    print("[*] Initializing Trainer for a quick test run (3 steps)...")
    training_args = TrainingArguments(
        output_dir=OUTPUT_DIR,
        per_device_train_batch_size=1,
        gradient_accumulation_steps=1,
        learning_rate=2e-4,
        logging_steps=1,
        max_steps=3, # ONLY RUN 3 STEPS FOR TESTING
        optim="adamw_torch",
        save_strategy="no", # don't save intermediate checkpoints for a test
        report_to="none" # disable wandb/tensorboard logging for the test
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=tokenized_dataset,
        data_collator=DataCollatorForLanguageModeling(tokenizer, mlm=False),
    )

    # 7. Run Test Training
    print("[*] Starting test training...")
    trainer.train()
    
    # 8. Save Test Adapter
    print(f"[*] Saving test adapter to {OUTPUT_DIR}")
    model.save_pretrained(OUTPUT_DIR)
    tokenizer.save_pretrained(OUTPUT_DIR)
    
    print("[+] Success! The fine-tuning pipeline works on your system.")

if __name__ == "__main__":
    main()
