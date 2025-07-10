import os
import json
import traceback

print("--- DIAGNOSTIC SCRIPT v5 START ---")

# --- Step 1: Check the Environment ---
print("\n--- Checking files in the current directory ---")
try:
    current_directory = os.getcwd()
    print(f"Current Working Directory: {current_directory}")
    all_files = os.listdir('.')
    print("Files found:")
    for f in all_files:
        print(f"- {f}")
except Exception as e:
    print(f"ERROR: Could not list directory contents. Reason: {e}")

# --- Step 2: Check requirements.txt content ---
print("\n--- Checking contents of requirements.txt ---")
try:
    with open('requirements.txt', 'r') as f:
        content = f.read()
        print("requirements.txt contains:")
        print(content)
        if 'telethon' not in content:
            print("\n*** CRITICAL WARNING: 'telethon' is NOT in requirements.txt! ***\n")
except FileNotFoundError:
    print("--- FATAL: requirements.txt does not exist! ---")
except Exception as e:
    print(f"ERROR: Could not read requirements.txt. Reason: {e}")


# --- Step 3: Attempt to load the JSON files ---
def json_load_safe(path):
    print(f"\n--- Attempting to load JSON file: '{path}' ---")
    try:
        with open(path, 'r', encoding='utf-8') as file:
            data = json.load(file)
            print(f"SUCCESS: Successfully loaded '{path}'. Found {len(data)} items.")
            return data
    except FileNotFoundError:
        print(f"--> FATAL_FIND_ERROR: The file '{path}' was not found at this location.")
        return []
    except json.JSONDecodeError as e:
        print(f"--> FATAL_JSON_ERROR: The file '{path}' is not valid JSON. Error: {e}")
        return []
    except Exception as e:
        print(f"--> FATAL_UNKNOWN_ERROR: An unknown error occurred reading '{path}'. Reason: {e}")
        return []

# --- Main execution block ---
print("\n--- Starting main data loading ---")
telegram_channels = json_load_safe('telegram channels.json')
subscription_links = json_load_safe('subscription links.json')

if not telegram_channels:
    print("\n--- RESULT: The 'telegram channels' list is EMPTY. ---")

if not subscription_links:
    print("\n--- RESULT: The 'subscription links' list is EMPTY. ---")


# --- Step 4: Check if Telethon can be imported ---
print("\n--- Checking if Telethon can be imported ---")
try:
    from telethon.sync import TelegramClient
    print("SUCCESS: Telethon module was imported correctly.")
except ModuleNotFoundError:
    print("\n*** FATAL_IMPORT_ERROR: 'telethon' module is NOT installed in this environment. ***\n")
except Exception as e:
    print(f"ERROR: An unknown error occurred during Telethon import. Reason: {e}")


print("\n--- DIAGNOSTIC SCRIPT END ---")
