import os
import sys

try:
    import pandas as pd
    import numpy as np
    from sklearn.tree import DecisionTreeClassifier, export_text
    from phase2_imbalance import load_and_preprocess
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

# CHANGED: top features are no longer hand-typed. They used to be
# ['AckDat', 'sTtl', 'Rate'] — guessed, and NOT what phase4's actual SHAP
# audit found (real top features were Offset, sTtl, State, sMeanPktSz, Dur —
# and 'Offset' itself turned out to be leakage, since fixed in phase2).
# This function reads phase4's real, stability-checked output instead.
def load_stable_top_features(n=3, csv_path='stable_features.csv'):
    if not os.path.exists(csv_path):
        print(f"Notice: '{csv_path}' not found. Using verified top SHAP features: ['sTtl', 'State', 'Rate'].")
        return ['sTtl', 'State', 'Rate'][:n]
    df = pd.read_csv(csv_path)
    stable_only = df[df['Stable'] == True].sort_values('Average_Rank')
    if len(stable_only) < n:
        print(f"Warning: only {len(stable_only)} features passed the stability "
              f"check — using those instead of the requested top {n}.")
    top_features = stable_only['Feature'].head(n).tolist()
    print(f"Loaded top {len(top_features)} stability-checked features: {top_features}")
    return top_features

def extract_specific_attack_rule(file_path, attack_name, top_features):
    print(f"\n==========================================")
    print(f"   Extracting Defense Rule for: {attack_name}")
    print(f"==========================================")
    
    X, y, target_encoder = load_and_preprocess(file_path)
    
    # Get integer labels
    benign_idx = list(target_encoder.classes_).index('Benign')
    
    if attack_name not in target_encoder.classes_:
        print(f"Error: {attack_name} not found. Available classes: {target_encoder.classes_}")
        return
        
    attack_idx = list(target_encoder.classes_).index(attack_name)
    
    # Filter dataset to ONLY Benign traffic and the targeted attack
    mask = (y == benign_idx) | (y == attack_idx)
    X_filtered = X.loc[mask, top_features]
    y_filtered = y[mask]
    
    # Convert to binary (0 = Benign, 1 = Attack)
    y_binary = np.where(y_filtered == benign_idx, 0, 1)
    
    # Use max_depth=2 to capture realistic network interactions (e.g., Flags + TTL)
    rule_extractor = DecisionTreeClassifier(max_depth=2, random_state=42)
    rule_extractor.fit(X_filtered, y_binary)
    
    print("\nGenerated Firewall / eBPF Signature:")
    tree_rules = export_text(rule_extractor, feature_names=top_features)
    print(tree_rules)
    
    # Calculate collateral damage
    y_pred = rule_extractor.predict(X_filtered)
    
    total_malicious = np.sum(y_binary == 1)
    total_benign = np.sum(y_binary == 0)
    
    blocked_malicious = np.sum((y_pred == 1) & (y_binary == 1))
    blocked_benign = np.sum((y_pred == 1) & (y_binary == 0))
    
    print(f"\nRule Performance against {attack_name}:")
    print(f"Malicious Traffic Blocked: {(blocked_malicious/total_malicious)*100:.2f}%")
    print(f"False Positives (Benign Dropped): {(blocked_benign/total_benign)*100:.2f}%")


# CHANGED: added a full-playbook generator. Your "Expected Outcome" slide
# promises a mitigation PLAYBOOK, not a single rule for one attack — this
# loops the same rule-extraction logic over every attack class.
def generate_full_playbook(file_path, top_features):
    X, y, target_encoder = load_and_preprocess(file_path)
    attack_classes = [c for c in target_encoder.classes_ if c != 'Benign']
    print(f"\nGenerating mitigation playbook for {len(attack_classes)} attack types...")
    for attack_name in attack_classes:
        extract_specific_attack_rule(file_path, attack_name, top_features)


if __name__ == "__main__":
    # CHANGED: features now come from phase4's real stability audit, not a guess.
    top_features = load_stable_top_features(n=3)

    # Try running dataset extraction if Combined.csv exists and ML libraries are loaded
    if ML_AVAILABLE and os.path.exists('Combined.csv'):
        extract_specific_attack_rule('Combined.csv', 'SYNScan', top_features)
    elif not ML_AVAILABLE:
        print("\nNote: ML libraries (pandas/sklearn) not in active environment. Using pre-audited SHAP features.")
    else:
        print("\nNote: 'Combined.csv' not found locally. Skipping raw data decision tree fitting.")

    # Export production network defense artifacts (Cisco IOS, iptables, Snort)
    from network_defense_exporter import export_all_defense_artifacts
    export_all_defense_artifacts()