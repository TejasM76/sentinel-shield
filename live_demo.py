import webbrowser
import time
import pyautogui
import sys

# We know the app is running here from the previous Streamlit boot
URL = "http://localhost:8508"

print("[Live Demo] Opening browser to Sentinel Shield...")
webbrowser.open(URL)

# Give the browser time to open and load the Streamlit page
time.sleep(5)

print("[Live Demo] Taking control of keyboard to type 'hi'...")
# Ensure window is focused
pyautogui.click(x=500, y=500) 
time.sleep(1)

# Press Tab multiple times to focus the chat input box (Streamlit UI routing)
pyautogui.press('tab')
pyautogui.press('tab')
pyautogui.press('tab')
time.sleep(0.5)

# Type the message and hit enter
pyautogui.write("hi", interval=0.2)
time.sleep(1)
pyautogui.press('enter')

print("[Live Demo] Message Sent! Please watch your browser window as Sentinel Shield scans and responds.")
sys.exit(0)
