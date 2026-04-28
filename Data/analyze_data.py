import os
import json
import pandas as pd


def analyze_txt(file):
    try:
        with open(file, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        print(f"\n📄 FILE: {file}")
        print("Type: TXT")
        print("Lines:", len(lines))

        print("\nFirst 5 lines:")
        for l in lines[:5]:
            print(l.strip())

    except Exception as e:
        print(f"Error reading {file}: {e}")


def analyze_csv(file):
    try:
        df = pd.read_csv(file)

        print(f"\n📄 FILE: {file}")
        print("Type: CSV")

        print("Columns:")
        print(df.columns.tolist())

        print("\nShape:")
        print(df.shape)

        print("\nSample:")
        print(df.head())

    except Exception as e:
        print(f"Error reading {file}: {e}")


def analyze_json(file):
    try:
        with open(file, "r", encoding="utf-8") as f:
            data = json.load(f)

        print(f"\n📄 FILE: {file}")
        print("Type: JSON")

        if isinstance(data, list):
            print("JSON List length:", len(data))
            if len(data) > 0:
                print("\nSample element:")
                print(data[0])

        elif isinstance(data, dict):
            print("Keys:")
            print(list(data.keys()))

    except Exception as e:
        print(f"Error reading {file}: {e}")


def analyze_file(file):

    size = os.path.getsize(file) / 1024

    print("\n==============================")
    print(f"FILE: {file}")
    print(f"SIZE: {size:.2f} KB")

    ext = file.split(".")[-1].lower()

    if ext == "txt":
        analyze_txt(file)

    elif ext == "csv":
        analyze_csv(file)

    elif ext == "json":
        analyze_json(file)

    else:
        print("Unknown file type")


def main():

    print("🔎 DATASET ANALYSIS")
    print("============================")

    # المرور على كل المجلدات
    for root, dirs, files in os.walk("."):

        for file in files:

            if file.endswith((".txt", ".csv", ".json")):

                full_path = os.path.join(root, file)

                analyze_file(full_path)


if __name__ == "__main__":
    main()