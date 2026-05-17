import os
import pandas as pd
import glob
from pathlib import Path

def clean_and_merge_datasets():
    print("=" * 60)
    print("  SMART-HUNTER Dataset Cleaner & Merger")
    print("=" * 60)

    base_dir = Path(__file__).parent
    source_dir = base_dir / "Datasets" / "Dataets_for_targetscan"
    output_dir = base_dir / "Cleaned_Datasets"
    
    if not source_dir.exists():
        print(f"Error: Source directory {source_dir} not found.")
        return
        
    output_dir.mkdir(parents=True, exist_ok=True)
    print(f"[*] Reading CSV files from: {source_dir}")
    
    # Types of datasets
    dataset_types = {
        "recon_page": [],
        "recon_redirect_hop": [],
        "vulnerability_summary": []
    }
    
    # Group files by type
    all_files = list(source_dir.glob("*.csv"))
    print(f"[*] Found {len(all_files)} total CSV files.")
    
    for file_path in all_files:
        filename = file_path.name
        if "recon_page" in filename:
            dataset_types["recon_page"].append(file_path)
        elif "recon_redirect_hop" in filename:
            dataset_types["recon_redirect_hop"].append(file_path)
        elif "vulnerability_summary" in filename:
            dataset_types["vulnerability_summary"].append(file_path)
            
    for dtype, files in dataset_types.items():
        if not files:
            print(f"[-] No files found for type: {dtype}")
            continue
            
        print(f"\n[*] Processing {len(files)} files for type: {dtype}")
        
        df_list = []
        for file in files:
            try:
                df = pd.read_csv(file, on_bad_lines='skip')
                df_list.append(df)
            except Exception as e:
                print(f"  [!] Failed to read {file.name}: {e}")
                
        if df_list:
            # Concatenate all dataframes
            merged_df = pd.concat(df_list, ignore_index=True)
            initial_rows = len(merged_df)
            print(f"  [+] Merged {initial_rows} rows.")
            
            # Drop duplicates
            merged_df.drop_duplicates(inplace=True)
            print(f"  [+] Removed {initial_rows - len(merged_df)} duplicate rows.")
            
            # Fill missing numerical values with 0 and strings with empty string, but keep URLs if any
            # For simplicity, we just drop columns that are entirely empty
            merged_df.dropna(axis=1, how='all', inplace=True)
            
            # Basic cleaning: Fill NaN values intelligently based on datatype
            for col in merged_df.columns:
                if merged_df[col].dtype == 'object':
                    merged_df[col] = merged_df[col].fillna('')
                else:
                    merged_df[col] = merged_df[col].fillna(0)
            
            output_file = output_dir / f"clean_merged_{dtype}.csv"
            merged_df.to_csv(output_file, index=False)
            print(f"  [+] Saved cleaned dataset to: {output_file.name} (Rows: {len(merged_df)}, Columns: {len(merged_df.columns)})")

    print(f"\n{'=' * 60}")
    print(f"  Done! Cleaned datasets saved to {output_dir}")
    print(f"{'=' * 60}")

if __name__ == "__main__":
    clean_and_merge_datasets()
