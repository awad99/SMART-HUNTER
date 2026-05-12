import os
import pandas as pd


# ---------------------------------------------------------------------------
# Minimum sample thresholds — below these the data is too sparse to train a
# meaningful model, so we log a warning instead of blindly oversampling.
# ---------------------------------------------------------------------------
MIN_SAMPLES_FOR_OVERSAMPLE = 10   # per-class floor before we allow upsample
MAX_SAMPLES_PER_CLASS = 5000      # cap to prevent huge classes from dominating


def prepare_dataset(requests_csv, responses_csv, labels_csv, output_csv):
    """Merge HTTP trace CSVs, filter to confirmed/reviewed labels only,
    build multi-modal text prompts, and write the transformer training set.
    """
    print("Loading datasets...")
    try:
        req_df = pd.read_csv(requests_csv)
        resp_df = pd.read_csv(responses_csv)
        lbl_df = pd.read_csv(labels_csv)
    except Exception as e:
        print(f"Error loading datasets. Ensure the CSV files exist. Details: {e}")
        return

    print("Merging datasets on trace_id...")
    df = req_df.merge(resp_df, on='trace_id', how='left', suffixes=('', '_resp'))
    df = df.merge(lbl_df, on='trace_id', how='left', suffixes=('', '_lbl'))

    # ------------------------------------------------------------------
    # FIX: Prefer confirmed labels; fall back to candidate ONLY when
    #      human_reviewed is True.  Reject everything else.
    # ------------------------------------------------------------------
    def _effective_label(row):
        confirmed = row.get('label_confirmed_family')
        if pd.notna(confirmed) and str(confirmed).strip():
            return str(confirmed).strip()
        candidate = row.get('label_candidate_family')
        reviewed = row.get('human_reviewed')
        if pd.notna(candidate) and str(candidate).strip():
            # Accept candidate only if a human confirmed it
            if str(reviewed).strip().lower() in ('true', '1', 'yes'):
                return str(candidate).strip()
        return None

    df['effective_label'] = df.apply(_effective_label, axis=1)

    initial_len = len(df)
    df = df.dropna(subset=['effective_label'])
    df = df[df['effective_label'] != '']
    dropped = initial_len - len(df)
    print(f"Dropped {dropped} traces without confirmed/reviewed labels.")

    if df.empty:
        print("[!] No traces with confirmed labels available. "
              "Collect more data or manually review labels before training.")
        return

    # ------------------------------------------------------------------
    # Handle Class Imbalance — only oversample when we have enough real
    # examples to learn a meaningful pattern.
    # ------------------------------------------------------------------
    family_counts = df['effective_label'].value_counts()
    print("\nConfirmed Label Distribution:")
    print(family_counts)

    balanced_dfs = []
    for family, count in family_counts.items():
        subset = df[df['effective_label'] == family]
        if count > MAX_SAMPLES_PER_CLASS:
            # Undersample large classes
            subset = subset.sample(n=MAX_SAMPLES_PER_CLASS, random_state=42)
        elif count < MIN_SAMPLES_FOR_OVERSAMPLE:
            # Too few examples — keep as-is but warn
            print(f"  [!] '{family}' has only {count} samples — too few to "
                  f"oversample reliably.  Keeping original rows.")
        # No blind oversampling — we keep whatever we have
        balanced_dfs.append(subset)

    if balanced_dfs:
        df_balanced = pd.concat(balanced_dfs)
    else:
        df_balanced = df

    print("\nFinal Class Distribution:")
    print(df_balanced['effective_label'].value_counts())

    # ------------------------------------------------------------------
    # Build multi-modal prompts — use the *_text field names that the
    # NLPTraceWriter and HTTPTraceBuilder now produce.
    # ------------------------------------------------------------------
    print("\nBuilding Multi-Modal Prompts for Transformers...")

    def build_prompt(row):
        return (
            f"REQUEST_METHOD: {row.get('method_text', '')}\n"
            f"TARGET_ROUTE: {row.get('route_template_text', '')}\n"
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

    # Add data-quality column so downstream consumers know the provenance
    df_balanced['data_quality'] = df_balanced.apply(
        lambda r: 'confirmed' if pd.notna(r.get('label_confirmed_family'))
                                 and str(r.get('label_confirmed_family')).strip()
                  else 'human_reviewed_candidate',
        axis=1,
    )

    final_df = df_balanced[[
        'trace_id', 'text_prompt', 'effective_label',
        'label_confirmed_family', 'data_quality',
    ]].rename(columns={'effective_label': 'label'})

    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    final_df.to_csv(output_csv, index=False)
    print(f"\nSuccess! Saved transformer dataset to: {output_csv}")


if __name__ == "__main__":
    base_dir = os.path.abspath(os.path.join(
        os.path.dirname(__file__), '..', '..', 'Data', 'Datasets',
        'Datasets_for_Model_NLP', 'http',
    ))
    requests_path = os.path.join(base_dir, 'http_trace_requests.csv')
    responses_path = os.path.join(base_dir, 'http_trace_responses.csv')
    labels_path = os.path.join(base_dir, 'http_trace_labels.csv')
    output_path = os.path.join(base_dir, 'transformer_training_data.csv')

    prepare_dataset(requests_path, responses_path, labels_path, output_path)
