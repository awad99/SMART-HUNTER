import os
import pandas as pd
from sklearn.utils import resample

def prepare_dataset(requests_csv, responses_csv, labels_csv, output_csv):
    print("Loading datasets...")
    try:
        req_df = pd.read_csv(requests_csv)
        resp_df = pd.read_csv(responses_csv)
        lbl_df = pd.read_csv(labels_csv)
    except Exception as e:
        print(f"Error loading datasets. Ensure the CSV files exist. Details: {e}")
        return

    print("Merging datasets on trace_id...")
    # Using suffixes to handle overlapping column names except trace_id
    df = req_df.merge(resp_df, on='trace_id', how='left', suffixes=('', '_resp'))
    df = df.merge(lbl_df, on='trace_id', how='left', suffixes=('', '_lbl'))

    # Drop traces without labels
    initial_len = len(df)
    df = df.dropna(subset=['label_candidate_family'])
    print(f"Dropped {initial_len - len(df)} traces with missing labels.")
    
    # Handle Class Imbalance
    family_counts = df['label_candidate_family'].value_counts()
    print("\nOriginal Class Distribution:")
    print(family_counts)

    MAX_SAMPLES = 5000
    MIN_SAMPLES = 500

    balanced_dfs = []
    for family, count in family_counts.items():
        subset = df[df['label_candidate_family'] == family]
        if count > MAX_SAMPLES:
            # Undersample
            subset = resample(subset, replace=False, n_samples=MAX_SAMPLES, random_state=42)
        elif count < MIN_SAMPLES:
            # Oversample
            subset = resample(subset, replace=True, n_samples=MIN_SAMPLES, random_state=42)
        balanced_dfs.append(subset)
    
    if balanced_dfs:
        df_balanced = pd.concat(balanced_dfs)
    else:
        df_balanced = df

    print("\nBalanced Class Distribution:")
    print(df_balanced['label_candidate_family'].value_counts())

    print("\nBuilding Multi-Modal Prompts for Transformers...")
    def build_prompt(row):
        return (
            f"REQUEST_METHOD: {row.get('method', '')}\n"
            f"TARGET_ROUTE: {row.get('route_template', '')}\n"
            f"QUERY_SHAPES: {row.get('query_shapes_text', '')}\n"
            f"HEADER_SEMANTICS: {row.get('request_header_semantic_text', '')}\n"
            f"ANOMALY_SCORE: {row.get('header_anomaly_score', '')}\n"
            f"BODY_CONTENT: {row.get('request_body_text', '')}\n"
            f"---\n"
            f"RESPONSE_STATUS: {row.get('status_code', '')}\n"
            f"RESPONSE_BODY_SNIPPET: {row.get('body_snippet_text', '')}\n"
            f"ERROR_SIGNATURES: {row.get('error_signatures_text', '')}"
        )

    df_balanced['text_prompt'] = df_balanced.apply(build_prompt, axis=1)
    
    # Save the final dataset
    final_df = df_balanced[['trace_id', 'text_prompt', 'label_candidate_family', 'label_confirmed_family']]
    
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    
    final_df.to_csv(output_csv, index=False)
    print(f"\nSuccess! Saved transformer dataset to: {output_csv}")

if __name__ == "__main__":
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'Data', 'Datasets', 'Datasets_for_Model_NLP', 'http'))
    requests_path = os.path.join(base_dir, 'http_trace_requests.csv')
    responses_path = os.path.join(base_dir, 'http_trace_responses.csv')
    labels_path = os.path.join(base_dir, 'http_trace_labels.csv')
    output_path = os.path.join(base_dir, 'transformer_training_data.csv')
    
    prepare_dataset(requests_path, responses_path, labels_path, output_path)
